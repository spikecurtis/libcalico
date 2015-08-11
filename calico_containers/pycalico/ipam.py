# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from etcd import EtcdKeyNotFound, EtcdAlreadyExist

from netaddr import IPAddress, IPNetwork
from types import NoneType
import socket
import json
import logging
import random

from pycalico.datastore_datatypes import IPPool
from pycalico.datastore import CALICO_V_PATH, DatastoreClient, handle_errors
from pycalico.datastore_errors import PoolNotFound
from pycalico.block import (AllocationBlock,
                            get_block_cidr_for_address,
                            BLOCK_PREFIXLEN,
                            AlreadyAssignedError)

_log = logging.getLogger(__name__)

IPAM_V_PATH = "/calico/ipam/v1/"
IPAM_HOST_PATH = IPAM_V_PATH + "host/%(hostname)s/"
IPAM_HOST_AFFINITY_PATH = IPAM_HOST_PATH + "ipv%(version)d/block/"
IPAM_BLOCK_PATH = IPAM_V_PATH + "assignment/ipv%(version)d/block/"
RETRIES = 100

my_hostname = socket.gethostname()


class BlockReaderWriter(DatastoreClient):
    """
    Can read and write allocation blocks to the data store, as well as related
    bits of state.

    This class keeps etcd specific code from being in the main IPAMClient
    class.
    """

    def _read_block(self, block_cidr):
        """
        Read the block from the data store.
        :param block_cidr: The IPNetwork identifier for a block.
        :return: An AllocationBlock object
        """
        key = _datastore_key(block_cidr)
        try:
            result = self.etcd_client.read(key)
        except EtcdKeyNotFound:
            raise KeyError(str(block_cidr))
        block = AllocationBlock.from_etcd_result(result)
        return block

    def _compare_and_swap_block(self, block):
        """
        Write the block using an atomic Compare-and-swap.
        """

        # If the block has a db_result, CAS against that.
        if block.db_result is not None:
            try:
                self.etcd_client.update(block.update_result())
            except EtcdAlreadyExist:
                raise CASError(str(block.cidr))
        else:
            # Block is new.  Write it with prevExist=False
            key = _datastore_key(block.cidr)
            value = block.to_json()
            try:
                self.etcd_client.write(key, value, prevExist=False)
            except EtcdAlreadyExist:
                raise CASError(str(block.cidr))

    def _get_affine_blocks(self, host, version, pool):
        """
        Get the blocks for which this host has affinity.

        :param host: The host name to get affinity for.
        :param version: 4 for IPv4, 6 for IPv6.
        :param pool: Limit blocks to a specific pool, or pass None to find all
        blocks for the specified version.
        """
        # Construct the path
        path = IPAM_HOST_AFFINITY_PATH % {"hostname": host,
                                          "version": version}
        block_ids = []
        try:
            result = self.etcd_client.read(path).children
            for child in result:
                packed = child.key.split("/")
                if len(packed) == 9:
                    # block_ids are encoded 192.168.1.0/24 -> 192.168.1.0-24
                    # in etcd.
                    block_ids.append(IPNetwork(packed[8].replace("-", "/")))
        except EtcdKeyNotFound:
            # Means the path is empty.
            pass

        # If pool specified, filter to only include ones in the pool.
        if pool is not None:
            assert isinstance(pool, IPPool)
            block_ids = [cidr for cidr in block_ids if cidr in pool]

        return block_ids

    def _new_affine_block(self, host, version, pool):
        """
        Create and register a new affine block for the host.

        :param host: The host name to get a block for.
        :param version: 4 for IPv4, 6 for IPv6.
        :param pool: Limit blocks to a specific pool, or pass None to find all
        blocks for the specified version.
        :return: The block CIDR of the new block.
        """
        # Get the pools and verify we got a valid one, or none.
        ip_pools = self.get_ip_pools(version)
        if pool is not None:
            if pool not in ip_pools:
                raise ValueError("Requested pool %s is not configured or has"
                                 "wrong attributes" % pool)
            # Confine search to only the one pool.
            ip_pools = [pool]

        for pool in ip_pools:
            for block_cidr in pool.cidr.subnet(BLOCK_PREFIXLEN[version]):
                block_id = str(block_cidr)
                _log.debug("Checking if block %s is free.", block_id)
                key = _datastore_key(block_cidr)
                try:
                    _ = self.etcd_client.read(key)
                except EtcdKeyNotFound:
                    _log.debug("Found block %s free.", block_id)
                    try:
                        self._claim_block_affinity(host, block_cidr)
                    except KeyError:
                        # Failed to claim the block because some other host
                        # has it.
                        _log.debug("Failed to claim block %s", block_cidr)
                        continue
                    # Success!
                    return block_cidr
        raise NoFreeBlocksError()

    def _claim_block_affinity(self, host, block_cidr):
        """
        Claim a block we think is free.
        """
        block_id = str(block_cidr)
        path = IPAM_HOST_AFFINITY_PATH % {"hostname": host,
                                          "version": block_cidr.version}
        key = path + block_id.replace("/", "-")
        self.etcd_client.write(key, "")

        # Create the block.
        block = AllocationBlock(block_cidr, host)
        try:
            self._compare_and_swap_block(block)
        except CASError:
            # Block exists.  Read it back to find out its host affinity
            block = self._read_block(block_cidr)
            if block.host_affinity == host:
                # Block is now claimed by us.  Some other process on this host
                # must have claimed it.
                _log.debug("Block %s already claimed by us. Success.",
                           block_cidr)
                return

            # Some other host beat us to claiming this block.  Clean up.
            self.etcd_client.delete(key)

            # Throw a key error to let the caller know the block wasn't free
            # after all.

            raise KeyError(block_id)
        # successfully created the block.  Done.
        return

    def _random_blocks(self, excluded_ids, version, pool):
        """
        Get an list of block CIDRs, in random order.

        :param excluded_ids: List of IDs that should be excluded.
        :param version: The IP version 4, or 6.
        :param pool: IPPool to get blocks from, or None to use all pools
        :return: An iterator of block CIDRs.
        """

        # Get the pools and verify we got a valid one, or none.
        ip_pools = self.get_ip_pools(version)
        if pool is not None:
            if pool not in ip_pools:
                raise ValueError("Requested pool %s is not configured or has"
                                 "wrong attributes" % pool)
            # Confine search to only the one pool.
            ip_pools = [pool]

        random_blocks = []
        i = 0
        for pool in ip_pools:
            for block_cidr in pool.cidr.subnet(BLOCK_PREFIXLEN[version]):
                if block_cidr not in excluded_ids:
                    # add this block.  We use an "inside-out" Fisher-Yates
                    # shuffle to randomize the list as we create it.  See
                    # http://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
                    j = random.randint(0, i)
                    if j != i:
                        random_blocks.append(random_blocks[j])
                        random_blocks[j] = block_cidr
                    else:
                        random_blocks.append(block_cidr)
                    i += 1
        return random_blocks


class CASError(Exception):
    """
    Compare-and-swap atomic update failed.
    """
    pass


class NoFreeBlocksError(Exception):
    """
    Tried to get a new block but there are none available.
    """
    pass


def _datastore_key(block_cidr):
    """
    Translate a block_id into a datastore key.
    :param block_cidr: IPNetwork representing the block
    :return: etcd key as string.
    """
    path = IPAM_BLOCK_PATH % {'version': block_cidr.version}
    return path + str(block_cidr).replace("/", "-")


class IPAMClient(BlockReaderWriter):

    def auto_assign_ips(self, num_v4, num_v6, primary_key, attributes,
                        pool=(None, None)):
        """
        Automatically pick and assign the given number of IPv4 and IPv6 addresses.

        :param num_v4: Number of IPv4 addresses to request
        :param num_v6: Number of IPv6 addresses to request
        :param primary_key: allocation primary key for this request.  You can query
        this key using get_assignments_by_key() or release all addresses with
        this key using release_by_key().
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must be
        JSON serializable.
        :param pool: (optional) tuple of (v4 pool, v6 pool); if supplied, the
        pool(s) to assign from,  If None, automatically choose a pool.
        :return: A tuple of (v4_address_list, v6_address_list).  When IPs in
        configured pools are at or near exhaustion, this method may return
        fewer than requested addresses.
        """

        v4_address_list = self._auto_assign(4, num_v4, primary_key,
                                            attributes, pool[0])
        v6_address_list = self._auto_assign(6, num_v6, primary_key,
                                            attributes, pool[1])
        return v4_address_list, v6_address_list

    def _auto_assign(self, ip_version, num, primary_key, attributes, pool):
        """
        Auto assign addresses from a specific IP version.

        Hosts automatically register themselves as the owner of a block the
        first time they request an auto-assigned IP.  For auto-assignment, a
        host will allocate from a block it owns, or if all their currently
        owned blocks get full, it will register itself as the owner of a new
        block.  If all blocks are owned, and all the host's own blocks are
        full, it will pick blocks at random until it can fulfil the request.
        If you're really, really out of addresses, it will fail the request.

        :param ip_version: 4 or 6, the IP version number.
        :param num: Number of addresses to assign.
        :param primary_key: allocation primary key for this request.
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must
        be JSON serializable.
        :param pool: (optional) if supplied, the pool to assign from,  If None,
        automatically choose a pool.
        :return:
        """

        block_list = self._get_affine_blocks(my_hostname,
                                             ip_version,
                                             pool)
        block_ids = iter(block_list)
        allocated_ips = []

        num_remaining = num
        while num_remaining > 0:
            try:
                block_id = block_ids.next()
            except StopIteration:
                break
            ips = self._auto_assign_block(block_id,
                                          num_remaining,
                                          primary_key,
                                          attributes)
            allocated_ips.extend(ips)
            num_remaining = num - len(allocated_ips)

        # If there are still addresses to allocate, then we've run out of
        # blocks with affinity.  Try to fullfil address request by allocating
        # new blocks.
        retries = RETRIES
        while num_remaining > 0 and retries > 0:
            retries -= 1
            try:
                new_block = self._new_affine_block(my_hostname,
                                                   ip_version,
                                                   pool)
                # If successful, this creates the block and registers it to us.
            except NoFreeBlocksError:
                # No more blocks.
                break
            ips = self._auto_assign_block(new_block,
                                          num_remaining,
                                          primary_key,
                                          attributes)
            allocated_ips.extend(ips)
            num_remaining = num - len(allocated_ips)
        if retries == 0:  # pragma: no cover
            raise RuntimeError("Hit Max Retries.")

        # If there are still addresses to allocate, we've now tried all blocks
        # with some affinity to us, and tried (and failed) to allocate new
        # ones.  Our last option is a random hunt through any blocks we haven't
        # yet tried.
        if num_remaining > 0:
            random_blocks = iter(self._random_blocks(block_list,
                                                     ip_version,
                                                     pool))
        while num_remaining > 0:
            try:
                block_id = random_blocks.next()
            except StopIteration:
                break
            ips = self._auto_assign_block(block_id,
                                          num_remaining,
                                          primary_key,
                                          attributes,
                                          affinity_check=False)
            allocated_ips.extend(ips)
            num_remaining = num - len(allocated_ips)

        return allocated_ips

    def _auto_assign_block(self, block_id, num, primary_key, attributes,
                           affinity_check=True):
        """
        Automatically pick IPs from a block and commit them to the data store.

        :param block_id: The identifier for the block to read.
        :param num: The number of IPs to assign.
        :param primary_key: allocation primary key for this request.
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must be
        JSON serializable.
        :param affinity_check: True to enable checking the host has the
        affinity to the block, False to disable this check, for example, while
        randomly searching after failure to get affine block.
        :return: List of assigned IPs.
        """
        _log.debug("Auto-assigning from block %s", block_id)
        for _ in xrange(RETRIES):
            block = self._read_block(block_id)
            unconfirmed_ips = block.auto_assign(num=num,
                                                primary_key=primary_key,
                                                attributes=attributes,
                                                affinity_check=affinity_check)
            if len(unconfirmed_ips) == 0:
                # Block is full.
                return []
            try:
                self._compare_and_swap_block(block)
            except CASError:
                continue
            else:
                # Confirm the IPs.
                return unconfirmed_ips
        raise RuntimeError("Hit Max Retries.")  # pragma: no cover

    def assign_ip(self, address, primary_key, attributes):
        """
        Assign the given address.  Throws AlreadyAssignedError if the address is
        taken.

        :param address: IPAddress to assign.
        :param primary_key: allocation primary key for this request.  You can query
        this key using get_assignments_by_key() or release all addresses with
        this key using release_by_key().
        :param attributes: Contents of this dict will be stored with the
        assignment and can be queried using get_assignment_attributes().  Must be
        JSON serializable.
        :return: None.
        """
        assert isinstance(address, IPAddress)
        block_cidr = get_block_cidr_for_address(address)

        for _ in xrange(RETRIES):
            try:
                block = self._read_block(block_cidr)
            except KeyError:
                # Block doesn't exist.  Is it in a valid pool?
                pools = self.get_ip_pools(address.version)
                if any([address in pool for pool in pools]):
                    # Address is in a pool.  Create and claim the block.
                    try:
                        self._claim_block_affinity(my_hostname,
                                                   block_cidr)
                    except KeyError:
                        # Happens if something else claims the block between
                        # the read above and claiming it.
                        continue
                    # Block exists now, retry writing to it.
                    _log.debug("Claimed block %s", block_cidr)
                    continue
                else:
                    raise ValueError("%s is not in any configured pool" %
                                     address)

            # Try to assign.  Throws exception if already assigned -- let it.
            block.assign(address, primary_key, attributes)

            # Try to commit
            try:
                self._compare_and_swap_block(block)
                return  # Success!
            except CASError:
                continue
        raise RuntimeError("Hit max retries.")  # pragma: no cover

    def release_ips(self, addresses):
        """
        Release the given addresses.

        :param addresses: Set of IPAddresses to release (ok to mix IPv4 and
        IPv6).
        :return: Set of addresses that were already unallocated.
        """
        assert isinstance(addresses, (set, frozenset))
        unallocated = set()
        # sort the addresses into blocks
        addrs_by_block = {}
        for address in addresses:
            block_cidr = get_block_cidr_for_address(address)
            addrs = addrs_by_block.setdefault(block_cidr, set())
            addrs.add(address)

        # loop through blocks, CAS releasing.
        for block_cidr, addresses in addrs_by_block.iteritems():
            _log.debug("Releasing %d adddresses from block %s",
                       len(addresses), block_cidr)
            unalloc_block = self._release_block(block_cidr, addresses)
            unallocated = unallocated.union(unalloc_block)
        return unallocated

    def _release_block(self, block_cidr, addresses):
        """
        Release the given addresses from the block, using compare-and-swap to
        write the block.
        :param block_cidr: IPNetwork identifying the block
        :param addresses: List of addresses to release.
        :return: List of addresses that were already unallocated.
        """

        for _ in xrange(RETRIES):
            try:
                block = self._read_block(block_cidr)
            except KeyError:
                # Block doesn't exist, so all addresses are already
                # unallocated.
                return addresses
            unallocated = block.release(addresses)
            assert len(unallocated) <= len(addresses)
            if len(unallocated) == len(addresses):
                # All the addresses are already unallocated.
                return addresses
            # Try to commit
            try:
                self._compare_and_swap_block(block)
                return unallocated  # Success!
            except CASError:
                continue
        raise RuntimeError("Hit Max retries.")  # pragma: no cover


    def get_ip_assignments_by_key(self, primary_key):
        """
        Return a list of IPAddresses assigned to the key.
        :param primary_key: Key to query e.g. used on assign() or auto_assign().
        :return: List of IPAddresses
        """
        pass

    def release_ip_by_key(self, primary_key):
        """
        Release all addresses assigned to the key.

        :param primary_key:
        :return: None.
        """
        pass

    def get_assignment_attributes(self, address):
        """
        Return the attributes of a given address.

        :param address: IPAddress to query.
        :return: The attributes for the address as passed to auto_assign() or
        assign().
        """
        pass

    def assign_address(self, pool, address):
        """
        Deprecated in favor of assign_ip().

        Attempt to assign an IPAddress in a pool.
        Fails if the address is already assigned.
        The directory for storing assignments in this pool must already exist.
        :param IPPool or IPNetwork pool: The pool that the assignment is from.
        If pool is None, get the pool from datastore
        :param IPAddress address: The address to assign.
        :return: True if the allocation succeeds, false otherwise. An
        exception is thrown for any error conditions.
        :rtype: bool
        """
        pool = pool or self.get_pool(address)
        if pool is None:
            raise PoolNotFound("IP address %s does not belong to any "
                                 "configured pools" % address)

        if isinstance(pool, IPPool):
            pool = pool.cidr
        assert isinstance(pool, IPNetwork)
        assert isinstance(address, IPAddress)

        try:
            self.assign_ip(address, None, {})
            return True
        except AlreadyAssignedError:
            return False
        # Other exceptions indicate error conditions.

    def unassign_address(self, pool, address):
        """
        Deprecated in favor of release_ips()

        Unassign an IP from a pool.
        :param IPPool or IPNetwork pool: The pool that the assignment is from.
        If the pool is None, get the pool from datastore
        :param IPAddress address: The address to unassign.
        :return: True if the address was unassigned, false otherwise. An
        exception is thrown for any error conditions.
        :rtype: bool
        """
        pool = pool or self.get_pool(address)
        if pool is None:
            raise PoolNotFound("IP address %s does not belong to any "
                                 "configured pools" % address)

        if isinstance(pool, IPPool):
            pool = pool.cidr
        assert isinstance(pool, IPNetwork)
        assert isinstance(address, IPAddress)

        err = self.release_ips({address})
        if err:
            return False
        else:
            return True
