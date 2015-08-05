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
from netaddr import IPNetwork, IPAddress
from nose.tools import *
from mock import patch, ANY, call, Mock
import unittest
import json
from etcd import EtcdResult, Client, EtcdAlreadyExist, EtcdKeyNotFound

from pycalico.ipam import (IPAMClient, BlockReaderWriter,
                           CASError, NoFreeBlocksError, _datastore_key)
from pycalico.block import AllocationBlock
from pycalico.datastore_datatypes import IPPool
from block_test import _test_block_empty_v4, _test_block_empty_v6

network = IPNetwork("192.168.25.0/24")


class TestIPAMClient(unittest.TestCase):

    def setUp(self):
        self.client = IPAMClient()
        self.m_etcd_client = Mock(spec=Client)
        self.client.etcd_client = self.m_etcd_client

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign(self):
        """
        Mainline test of auto assign.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [IPNetwork("10.11.12.0/24"),
                    IPNetwork("10.11.45.0/24")]

        block = _test_block_empty_v4()
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.return_value = m_result

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(1, 0, None, {})
            assert_list_equal([IPAddress("10.11.12.0")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_dual(self):
        """
        Test of auto assign with both IPv4 and IPv6 requests.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            assert ip_version in [4, 6]
            if ip_version == 4:
                return [IPNetwork("10.11.12.0/24"),
                        IPNetwork("10.11.45.0/24")]
            else:
                return [IPNetwork("2001:abcd:def0::/120"),
                        IPNetwork("2001:abcd:def0::4500/120")]

        block0 = _test_block_empty_v4()
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        block1 = _test_block_empty_v6()
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()
        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(1, 2, None, {})
            assert_list_equal([IPAddress("10.11.12.0")], ipv4s)
            assert_list_equal([IPAddress("2001:abcd:def0::"),
                               IPAddress("2001:abcd:def0::1")], ipv6s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_1st_block_full(self):
        """
        Test auto assign when 1st block is full.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [IPNetwork("10.11.12.0/24"), IPNetwork("10.11.45.0/24")]

        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(256, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        block1 = _test_block_empty_v4()
        block1.cidr = IPNetwork("10.11.45.0/24")
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()

        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(1, 0, None, {})
            assert_list_equal([IPAddress("10.11.45.0")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_span_blocks(self):
        """
        Test auto assign when 1st block has fewer than requested addresses.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [IPNetwork("10.11.12.0/24"), IPNetwork("10.11.45.0/24")]

        # 1st block has 2 free addresses.
        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(254, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        # 2nd block is empty.
        block1 = _test_block_empty_v4()
        block1.cidr = IPNetwork("10.11.45.0/24")
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()

        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_list_equal([IPAddress("10.11.12.254"),
                               IPAddress("10.11.12.255"),
                               IPAddress("10.11.45.0"),
                               IPAddress("10.11.45.1")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_not_enough_addrs(self):
        """
        Test auto assign when there aren't enough addresses, and no free
        blocks.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [IPNetwork("10.11.12.0/24"), IPNetwork("10.11.45.0/24")]

        def m_get_ip_pools(self, version):
            # The two claimed blocks are the only pools.
            return [IPPool("10.11.12.0/24"), IPPool("10.11.45.0/24")]

        # 1st block has 2 free addresses.
        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(254, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        # 2nd block has 1 free address.
        block1 = _test_block_empty_v4()
        _ = block1.auto_assign(255, None, {}, affinity_check=False)
        block1.cidr = IPNetwork("10.11.45.0/24")
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block1.to_json()

        # Total of 4 reads: first two are checking blocks with affinity
        # second two are trying to find free blocks in the pool (but there
        # aren't any).
        self.m_etcd_client.read.side_effect = [m_result0, m_result1,
                                               m_result0, m_result1]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks),\
             patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_list_equal([IPAddress("10.11.12.254"),
                               IPAddress("10.11.12.255"),
                               IPAddress("10.11.45.255")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_cas_fails(self):
        """
        Test auto assign when 1st block compare-and-swap fails.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return [IPNetwork("10.11.12.0/24"), IPNetwork("10.11.45.0/24")]

        # 1st read, 1st block has 2 free addresses.
        block0 = _test_block_empty_v4()
        _ = block0.auto_assign(254, None, {}, affinity_check=False)
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block0.to_json()
        # 2nd read, 1st block has 1 free addresses.
        _ = block0.auto_assign(1, None, {}, affinity_check=False)
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block0.to_json()
        # 2nd block is empty.
        block1 = _test_block_empty_v4()
        block1.cidr = IPNetwork("10.11.45.0/24")
        m_result2 = Mock(spec=EtcdResult)
        m_result2.value = block1.to_json()

        # Read three times, update 3 times.
        self.m_etcd_client.read.side_effect = [m_result0, m_result1, m_result2]
        self.m_etcd_client.update.side_effect = [EtcdAlreadyExist(),
                                                 None,
                                                 None]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_list_equal([IPAddress("10.11.12.255"),
                               IPAddress("10.11.45.0"),
                               IPAddress("10.11.45.1"),
                               IPAddress("10.11.45.2")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_no_blocks(self):
        """
        Test auto assign when we haven't allocated blocks yet, but there are
        free blocks available.

        Order of operations
            1 Read first subnet in pool.  Doesn't exist.
            2 Write to affinity store for this host.
            3 Write an empty block
            4 Read back the block
            5 CAS update with allocated ips.
        """

        def m_get_affine_blocks(self, host, ip_version, pool):
            return []

        def m_get_ip_pools(self, version):
            return [IPPool("192.168.0.0/16")]

        # Reads on 1, 4
        block = AllocationBlock(IPNetwork("192.168.0.0/24"), "test_host1")
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.side_effect = [EtcdKeyNotFound(), m_result]


        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks),\
             patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_equal(self.m_etcd_client.read.call_count, 2)
            assert_list_equal([IPAddress("192.168.0.0"),
                               IPAddress("192.168.0.1"),
                               IPAddress("192.168.0.2"),
                               IPAddress("192.168.0.3")], ipv4s)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_auto_assign_random_blocks(self):
        """
        Test auto assign when all blocks our blocks are full and all other
        blocks already have host affinity.
        """

        affine_blocks = [IPNetwork("10.11.12.0/24"),
                         IPNetwork("10.11.45.0/24")]

        def m_get_affine_blocks(self, host, ip_version, pool):
            return affine_blocks

        rando_blocks = set()

        def m_read_block(self, block_cidr):
            if block_cidr in affine_blocks:
                # All our blocks are full.
                block = AllocationBlock(block_cidr, "test_host1")
                block.auto_assign(256, None, {})
            else:
                # Other blocks are not.
                block = AllocationBlock(block_cidr, "test_host2")
                rando_blocks.add(block)
            return block

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/18")]

        with patch("pycalico.ipam.BlockReaderWriter._get_affine_blocks",
                   m_get_affine_blocks),\
             patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools),\
             patch("pycalico.ipam.BlockReaderWriter._read_block",
                   m_read_block):
            (ipv4s, ipv6s) = self.client.auto_assign_ips(4, 0, None, {})
            assert_equal(len(ipv4s), 4)
            assert_equal(len(rando_blocks), 1)
            rando_block = rando_blocks.pop()
            for ip in ipv4s:
                assert_true(ip in rando_block.cidr)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_assign(self):
        """
        Mainline test of assign_ip().
        """

        block = _test_block_empty_v4()
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.return_value = m_result

        ip0 = IPAddress("10.11.12.55")
        self.client.assign_ip(ip0, None, {})
        self.m_etcd_client.update.assert_called_once_with(m_result)

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_assign_cas_fails(self):
        """
        Test assign_ip() when the compare-and-swap fails.
        """

        block = _test_block_empty_v4()
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block.to_json()
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block.to_json()
        self.m_etcd_client.read.side_effect = [m_result0, m_result1]

        # First update fails, then succeeds.
        self.m_etcd_client.update.side_effect = [EtcdAlreadyExist(),
                                                 None]

        ip0 = IPAddress("10.11.12.55")
        self.client.assign_ip(ip0, None, {})
        self.m_etcd_client.update.assert_has_calls([call(m_result0),
                                                    call(m_result1)])

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result1.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_assign_new_block(self):
        """
        Test assign_ip() when address is in a block that hasn't been written.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # 1st read, doesn't exist.  2nd read, does exist, empty.
        block = AllocationBlock(IPNetwork("10.11.12.0/24"), "test_host1")
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block.to_json()
        self.m_etcd_client.read.side_effect = [EtcdKeyNotFound(), m_result0]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            ip0 = IPAddress("10.11.12.55")
            self.client.assign_ip(ip0, None, {})

        # Verify we wrote a new block
        # Two calls to write() -- one for recording affinity, the other the
        # block itself
        assert_equal(self.m_etcd_client.write.call_count, 2)
        (args, kwargs) = self.m_etcd_client.write.call_args
        assert_dict_equal({"prevExist": False}, kwargs)

        # Allocation is via update
        self.m_etcd_client.update.assert_called_once_with(m_result0)
        json_dict = json.loads(m_result0.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)
        assert_dict_equal({"prevExist": False}, kwargs)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_assign_new_block_cas_error(self):
        """
        Test assign_ip() when address is in a new block.

        Order of events:
            1 Attempt to read the block.  It doesn't exist.
            2 Write block affinity
            3 Attempt to write a new block --- false because someone else wrote
              it before us.
            4 Re-read the block.
            5 Back out 2.
            6 Re-read the block.
            7 Compare-and-swap new allocation with read from 3.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # 2nd read.
        block = _test_block_empty_v4()
        block.assign(IPAddress("10.11.12.56"), None, {})
        m_result1 = Mock(spec=EtcdResult)
        m_result1.value = block.to_json()

        # Reads at 1, 4, 6
        self.m_etcd_client.read.side_effect = [EtcdKeyNotFound(),
                                               m_result1,
                                               m_result1]

        # Writes are 2, 3, 5 above.
        self.m_etcd_client.write.side_effect = [None,
                                                EtcdAlreadyExist(),
                                                None]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            ip0 = IPAddress("10.11.12.55")
            self.client.assign_ip(ip0, None, {})

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result1.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    @patch("pycalico.block.my_hostname", "test_host1")
    def test_assign_not_in_pools(self):
        """
        Test assign_ip() when address is not in configured pools.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # block doesn't exist.
        self.m_etcd_client.read.side_effect = EtcdKeyNotFound()

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            ip0 = IPAddress("10.12.12.55")
            assert_raises(ValueError, self.client.assign_ip, ip0, None, {})

        # Verify we did not write anything.
        assert_false(self.m_etcd_client.write.called)
        assert_false(self.m_etcd_client.update.called)

    def test_assign_address(self):
        """
        Mainline test of assign_address().
        """

        block = _test_block_empty_v4()
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.return_value = m_result

        ip0 = IPAddress("10.11.12.55")
        pool = IPPool("10.11.0.0/16")
        success = self.client.assign_address(pool, ip0)
        assert_true(success)
        self.m_etcd_client.update.assert_called_once_with(m_result)

        # Assert the JSON shows the address allocated.
        json_dict = json.loads(m_result.value)
        assert_equal(json_dict[AllocationBlock.ALLOCATIONS][55], 0)

    def test_assign_address_fails(self):
        """
        Test assign_address() when it fails.
        """
        ip0 = IPAddress("10.11.12.55")

        block = _test_block_empty_v4()
        block.assign(ip0, None, {})
        m_result = Mock(spec=EtcdResult)
        m_result.value = block.to_json()
        self.m_etcd_client.read.return_value = m_result

        pool = IPPool("10.11.0.0/16")
        success = self.client.assign_address(pool, ip0)
        assert_false(success)
        assert_false(self.m_etcd_client.update.called)

    def test_release_basic(self):
        """
        Basic test of release_ip
        """
        ip4 = IPAddress("10.11.12.13")
        ip6 = IPAddress("2001:abcd:def0::0045")
        m_result4 = Mock(spec=EtcdResult)
        m_result6 = Mock(spec=EtcdResult)
        def m_read_block(self, block_cidr):
            block4 = _test_block_empty_v4()
            block4.assign(ip4, None, {})
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            block6 = _test_block_empty_v6()
            block6.assign(ip6, None, {})
            block6.db_result = m_result6
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockReaderWriter._read_block",
                   m_read_block):
            ips = {ip4, ip6}
            err = self.client.release_ips(ips)
            assert_set_equal(err, set())

        self.m_etcd_client.update.assert_has_calls([call(m_result4),
                                                    call(m_result6)],
                                                   any_order=True)

    def test_release_already_unallocated(self):
        """
        Test release_ip when already unallocated.
        """
        ip4 = IPAddress("10.11.12.13")
        ip6 = IPAddress("2001:abcd:def0::0045")
        m_result4 = Mock(spec=EtcdResult)
        m_result6 = Mock(spec=EtcdResult)
        def m_read_block(self, block_cidr):
            block4 = _test_block_empty_v4()
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            block6 = _test_block_empty_v6()
            block6.db_result = m_result6
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockReaderWriter._read_block",
                   m_read_block):
            ips = {ip4, ip6}
            err = self.client.release_ips(ips)
            assert_set_equal(err, ips)


    def test_release_no_block(self):
        """
        Test release_ip when one block doesn't exist.
        """
        ip4 = IPAddress("10.11.12.13")
        ip6 = IPAddress("2001:abcd:def0::0045")
        m_result6 = Mock(spec=EtcdResult)
        def m_read_block(self, block_cidr):
            if block_cidr == IPNetwork("10.11.12/24"):
                raise KeyError
            block6 = _test_block_empty_v6()
            block6.assign(ip6, None, {})
            block6.db_result = m_result6
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockReaderWriter._read_block",
                   m_read_block):
            ips = {ip4, ip6}
            err = self.client.release_ips(ips)
            assert_set_equal(err, {ip4})

        # Assert we only wrote IPv6 block.
        self.m_etcd_client.update.assert_called_once_with(m_result6)

    def test_release_multiple(self):
        """
        Test of release_ip with multiple addresses in multiple blocks
        """
        ip4s = {IPAddress("10.11.12.13"), IPAddress("10.11.12.200")}
        ip6s = {IPAddress("2001:abcd:def0::0045"),
                IPAddress("2001:abcd:def0::00aa")}
        m_result4 = Mock(spec=EtcdResult)
        m_result6 = Mock(spec=EtcdResult)
        def m_read_block(self, block_cidr):
            block4 = _test_block_empty_v4()
            for ip4 in ip4s:
                block4.assign(ip4, None, {})
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            block6 = _test_block_empty_v6()
            for ip6 in ip6s:
                block6.assign(ip6, None, {})
            block6.db_result = m_result6
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockReaderWriter._read_block",
                   m_read_block):
            ips = ip4s.union(ip6s)
            err = self.client.release_ips(ips)
            assert_set_equal(err, set())

        self.m_etcd_client.update.assert_has_calls([call(m_result4),
                                                    call(m_result6)],
                                                   any_order=True)
        json_4 = json.loads(m_result4.value)
        assert_equal(json_4["allocations"][13], None)
        assert_equal(json_4["allocations"][200], None)
        json_6 = json.loads(m_result6.value)
        assert_equal(json_6["allocations"][0x45], None)
        assert_equal(json_6["allocations"][0xaa], None)

    def test_release_cas_error(self):
        """
        Test of release_ip when there is a CAS error.
        """
        ip4 = IPAddress("10.11.12.13")
        ip6 = IPAddress("2001:abcd:def0::0045")
        m_result4 = Mock(spec=EtcdResult)
        m_result6 = Mock(spec=EtcdResult)

        def m_read_block(self, block_cidr):
            block4 = _test_block_empty_v4()
            block4.assign(ip4, None, {})
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            block6 = _test_block_empty_v6()
            block6.assign(ip6, None, {})
            block6.db_result = m_result6
            if block_cidr == block6.cidr:
                return block6
            assert_true(False, "Unexpected block CIDR")

        # Throw an error the first time we write the v4 block, then allow.
        call_count = {4: 0, 6: 0}

        def m_compare_and_swap_block(self, block):
            call_count[block.cidr.version] += 1
            if block.cidr.version == 6:
                return
            else:
                # CAS error on first call
                if call_count[4] == 1:
                    raise CASError()
                else:
                    return

        with patch("pycalico.ipam.BlockReaderWriter._read_block",
                   m_read_block),\
             patch("pycalico.ipam.BlockReaderWriter._compare_and_swap_block",
                   m_compare_and_swap_block):
            ips = {ip4, ip6}
            err = self.client.release_ips(ips)
            assert_set_equal(err, set())

        assert_dict_equal(call_count, {4: 2, 6: 1})

    def test_unassign_address(self):
        """
        Basic test of unassign_address
        """
        ip4 = IPAddress("10.11.12.13")
        m_result4 = Mock(spec=EtcdResult)
        def m_read_block(self, block_cidr):
            block4 = _test_block_empty_v4()
            block4.assign(ip4, None, {})
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockReaderWriter._read_block",
                   m_read_block):
            pool = IPPool("10.11.0.0/16")
            success = self.client.unassign_address(pool, ip4)
            assert_true(success)

        self.m_etcd_client.update.assert_called_once_with(m_result4)

    def test_unassign_address_fails(self):
        """
        Test of unassign_address when it fails
        """
        ip4 = IPAddress("10.11.12.13")
        m_result4 = Mock(spec=EtcdResult)
        def m_read_block(self, block_cidr):
            block4 = _test_block_empty_v4()
            block4.db_result = m_result4
            if block_cidr == block4.cidr:
                return block4
            assert_true(False, "Unexpected block CIDR")

        with patch("pycalico.ipam.BlockReaderWriter._read_block",
                   m_read_block):
            pool = IPPool("10.11.0.0/16")
            success = self.client.unassign_address(pool, ip4)
            assert_false(success)

        assert_false(self.m_etcd_client.update.called)


class TestBlockReaderWriter(unittest.TestCase):

    def setUp(self):
        self.client = BlockReaderWriter()
        self.m_etcd_client = Mock(spec=Client)
        self.client.etcd_client = self.m_etcd_client

    def test_get_affine_blocks(self):
        """
        Test _get_affine_blocks mainline.
        """
        expected_ids = ["192.168.3.0/24", "192.168.5.0/24"]

        # Return some blocks.
        def m_read(path):
            assert path == "/calico/ipam/v1/host/test_host/ipv4/block/"
            result = Mock(spec=EtcdResult)
            children = []
            for net in expected_ids:
                node = Mock(spec=EtcdResult)
                node.value = ""
                node.key = path + net.replace("/", "-")
                children.append(node)
            result.children = iter(children)
            return result
        self.m_etcd_client.read.side_effect = m_read

        block_ids = self.client._get_affine_blocks("test_host", 4, None)
        assert_list_equal(block_ids, map(IPNetwork, expected_ids))

    def test_get_affine_blocks_empty(self):
        """
        Test _get_affine_blocks when there are no stored blocks.
        """
        expected_ids = []

        # Return some blocks.
        def m_read(path):
            assert path == "/calico/ipam/v1/host/test_host/ipv4/block/"
            result = Mock(spec=EtcdResult)
            result.children = iter([])
            return result
        self.m_etcd_client.read.side_effect = m_read

        block_ids = self.client._get_affine_blocks("test_host", 4, None)
        assert_list_equal(block_ids, expected_ids)

    def test_get_affine_blocks_key_error(self):
        """
        Test _get_affine_blocks when the host key doesn't exist.
        """
        expected_ids = []

        self.m_etcd_client.read.side_effect = EtcdKeyNotFound()

        block_ids = self.client._get_affine_blocks("test_host", 4, None)
        assert_list_equal(block_ids, expected_ids)

    def test_get_affine_blocks_pool(self):
        """
        Test _get_affine_blocks when filtering by IPPool
        """
        expected_ids = [IPNetwork("10.10.1.0/24")]
        returned_ids = ["192.168.3.0/24", "10.10.1.0/24"]

        # Return some blocks.
        def m_read(path):
            assert path == "/calico/ipam/v1/host/test_host/ipv4/block/"
            result = Mock(spec=EtcdResult)
            children = []
            for net in returned_ids:
                node = Mock(spec=EtcdResult)
                node.value = ""
                node.key = path + net.replace("/", "-")
                children.append(node)
            result.children = iter(children)
            return result
        self.m_etcd_client.read.side_effect = m_read

        ip_pool = IPPool(IPNetwork("10.0.0.0/8"))
        block_ids = self.client._get_affine_blocks("test_host", 4, ip_pool)
        assert_list_equal(block_ids, expected_ids)

    def test_claim_block_affinity_already_owned(self):
        """
        Test _claim_block_affinity() when we already own the block

        Order of events
        1 Write host affinity
        2 Try to write the new block, but this fails.
        3 Read the block, check its affinity
        """

        block = _test_block_empty_v4()
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block.to_json()

        # Reads at 3
        self.m_etcd_client.read.return_value = m_result0

        # Write at 1, 2
        self.m_etcd_client.write.side_effect = [None, EtcdAlreadyExist()]

        self.client._claim_block_affinity(block.host_affinity,
                                          block.cidr)

        key = _datastore_key(block.cidr)
        value = block.to_json()
        self.m_etcd_client.write.assert_has_calls([call(ANY, ""),
                                                   call(key, value,
                                                        prevExist=False)])
        self.m_etcd_client.read.assert_called_once_with(key)

    def test_new_affine_block_race(self):
        """
        Test _new_affine_block when another host claims it between reading
        and writing.

        1 Read shows block is free (EtcdKeyNotFound)
        2 Write host affinity
        3 Try to write the new block, but this fails
        4 Re-read the block, discover another host owns it
        5 Delete key from 2
        6 Read next block, find it free
        7 Write host affinity
        8 Try to write the new block, success
        """

        block = AllocationBlock(IPNetwork("10.11.0.0/24"), "test_host1")
        m_result0 = Mock(spec=EtcdResult)
        m_result0.value = block.to_json()

        # Reads at 1, 4, 6
        self.m_etcd_client.read.side_effect = [
            EtcdKeyNotFound(),  # 1
            m_result0,  # 4
            EtcdKeyNotFound()  # 6
        ]
        # Write at 2, 3, 7, 8
        self.m_etcd_client.write.side_effect = [
            None,  # 2
            EtcdAlreadyExist(),  # 3
            None,  # 7
            None  # 8
        ]

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):

            cidr = self.client._new_affine_block("test_host2", 4, None)
            assert_equal(cidr, IPNetwork("10.11.1.0/24"))

            # 1st block write is the .0.0 block, but with test_host2 affinity.
            key0 = _datastore_key(block.cidr)
            block.host_affinity = "test_host2"
            value0 = block.to_json()

            # 2nd block write is the .1.0 block.
            block1 = AllocationBlock(cidr, "test_host2")
            key1 = _datastore_key(cidr)
            value1 = block1.to_json()

            self.m_etcd_client.write.assert_has_calls([
                call(ANY, ""),
                call(key0, value0, prevExist=False),
                call(ANY, ""),
                call(key1, value1, prevExist=False)
            ])

    def test_new_affine_block_bad_pool(self):
        """
        Test _new_affine_block when the pool given doesn't match.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            assert_raises(ValueError,
                          self.client._new_affine_block,
                          "test_host1", 4, IPPool("10.11.0.0/8"))

    def test_new_affine_block_good_pool(self):
        """
        Test _new_affine_block limits to a single pool if requested.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"), IPPool("192.168.0.0/16")]

        # Reads are always successful
        self.m_etcd_client.read.return_value = Mock(spec=AllocationBlock)

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            assert_raises(NoFreeBlocksError,
                          self.client._new_affine_block,
                          "test_host1", 4, IPPool("10.11.0.0/16"))

            # Two /16 pools means 512 blocks to try.  Assert that we only
            # work the one pool, or 256 blocks.
            assert_equal(self.m_etcd_client.read.call_count, 256)

            # Spot check last call is the last subnet in 10.11.0.0/16 pool.
            assert_equal(self.m_etcd_client.read.call_args[0][0],
                         _datastore_key(IPNetwork("10.11.255.0/24")))

    def test_random_blocks(self):
        """
        Test _random_blocks() mainline.
        """
        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16")]

        excluded_ids = [IPNetwork("10.11.23.0/24"),
                        IPNetwork("10.11.45.0/24"),
                        IPNetwork("10.45.45.0/24")]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            random_blocks = self.client._random_blocks(excluded_ids, 4, None)

            # Excluded 3, but only 2 in the pool, so 256 - 2 = 254 blocks.
            assert_equal(len(random_blocks), 254)

            # Assert we correctly exclude IDs
            for cidr in excluded_ids:
                assert_not_in(cidr, random_blocks)

            # Spot check some cidrs
            assert_in(IPNetwork("10.11.0.0/24"), random_blocks)
            assert_in(IPNetwork("10.11.0.1/24"), random_blocks)
            assert_in(IPNetwork("10.11.0.255/24"), random_blocks)
            assert_in(IPNetwork("10.11.0.127/24"), random_blocks)

            # check we aren't doing something stupid, like returning the same
            # order every time.
            random_blocks2 = self.client._random_blocks(excluded_ids, 4, None)
            assert_equal(len(random_blocks2), 254)

            differs = False
            for ii in range(len(random_blocks2)):
                assert_in(random_blocks2[ii], random_blocks)
                if random_blocks[ii] != random_blocks2[ii]:
                    differs = True
            assert_true(differs)

    def test_random_blocks_bad_pool(self):
        """
        Test _random_blocks when the requested pool isn't in IPPools.
        """

        def m_get_ip_pools(self, version):
            return [IPPool("10.11.0.0/16"),
                    IPPool("192.168.0.0/16")]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            assert_raises(ValueError, self.client._random_blocks,
                          [], 4, IPPool("10.1.0.0/16"))

    def test_random_blocks_good_pool(self):
        """
        Test _random_blocks() when restricted to a single pool.
        """
        def m_get_ip_pools(self, version):
            return [IPPool("10.45.0.0/16"),
                    IPPool("10.11.0.0/16")]

        excluded_ids = [IPNetwork("10.11.23.0/24"),
                        IPNetwork("10.11.45.0/24"),
                        IPNetwork("10.45.45.0/24")]

        with patch("pycalico.datastore.DatastoreClient.get_ip_pools",
                   m_get_ip_pools):
            random_blocks = self.client._random_blocks(excluded_ids, 4,
                                                       IPPool("10.11.0.0/16"))

            # Excluded 3, but only 2 in the pool, so 256 - 2 = 254 blocks.
            assert_equal(len(random_blocks), 254)

            # Assert we correctly exclude IDs
            for cidr in excluded_ids:
                assert_not_in(cidr, random_blocks)

            # Spot check some cidrs
            assert_in(IPNetwork("10.11.0.0/24"), random_blocks)
            assert_in(IPNetwork("10.11.0.1/24"), random_blocks)
            assert_in(IPNetwork("10.11.0.255/24"), random_blocks)
            assert_in(IPNetwork("10.11.0.127/24"), random_blocks)






