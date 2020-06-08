import os, shutil
import unittest
from typing import NamedTuple

from electrum.util import to_bytes, bh2u
from electrum.header_storage import HeaderStorage


class HeaderCase(NamedTuple):
    height: int
    hex: str
    data: dict

# Check python code ./scripts/header-handle.py to see how test case data generated
HEADER_TEST_CASES = [
    HeaderCase(
        height=78190,
        hex='000000201558224c324622a5c44d8a8b945b228fec7b0990b1b547f8136c878b0b67060076d08f5fa7fc77322bb29f8c1de2034664cb7014db88802ca1675df27df2b0bf6e310100000000000000000000000000000000000000000000000000000000007e84d75effff071f8f1603000000000000000000000000000000000000000000000000002f0500003454bd11949162140d0f11ec97693b3f21fc590009d5e1a947a6f9d4c9a3e9e096b71e7a4032a5cedc057c5df35538729c1af2bf762f15812ad9e9546ab5066bfb2e25e6d5d277b55c5146998ebf36c135b92c4d47daf433ea157f2f25cdc70b11d61a14',
        data={
            'version': 536870912,
            'prev_block_hash': '0006670b8b876c13f847b5b190097bec8f225b948b8a4dc4a52246324c225815',
            'merkle_root': 'bfb0f27df25d67a12c8088db1470cb644603e21d8c9fb22b3277fca75f8fd076',
            'block_height': 78190,
            'reserved': '00000000000000000000000000000000000000000000000000000000',
            'timestamp': 1591182462,
            'bits': 0x1f07ffff,
            'nonce': '0000052f0000000000000000000000000000000000000000000000000003168f',
            'solution':'141ad6110bc7cd252f7f15ea33f4da474d2cb935c136bf8e9946515cb577d2d5e6252efb6b06b56a54e9d92a81152f76bff21a9c723855f35d7c05dccea532407a1eb796e0e9a3c9d4f9a647a9e1d5090059fc213f3b6997ec110f0d1462919411bd5434'
        }
    ),
    HeaderCase(
        height=78191,
        hex='0000002028ae36ad84e7aeb5259d397e8443af073827fd53ef46ad30ee15e07bb6e301001edcadb5ec345f23fd8d1d484820b8f69ba504d0227c00f4cb31dad5b82aed4a6f310100000000000000000000000000000000000000000000000000000000002892d75effff071f8f160700000000000000000000000000000000000000000000000000480000005ea571692c234a390ef670fcd74a1791c73e1a7150ff834368d61970ff2edb6563a1bc6297233416bff3a5b298a9e6f6843523637a7b5c9b8aa6c9862bcc866a4998d2d6ddcec13161ef5439d82c5914cffc8b4e8b6ae2d10dca3fc7bb06fc5585775c07',
        data={
            'version': 536870912,
            'prev_block_hash': '0001e3b67be015ee30ad46ef53fd273807af43847e399d25b5aee784ad36ae28',
            'merkle_root': '4aed2ab8d5da31cbf4007c22d004a59bf6b82048481d8dfd235f34ecb5addc1e',
            'block_height': 78191,
            'reserved': '00000000000000000000000000000000000000000000000000000000',
            'timestamp': 1591185960,
            'bits': 0x1f07ffff,
            'nonce': '000000480000000000000000000000000000000000000000000000000007168f',
            'solution':'075c778555fc06bbc73fca0dd1e26a8b4e8bfccf14592cd83954ef6131c1ceddd6d298496a86cc2b86c9a68a9b5c7b7a63233584f6e6a998b2a5f3bf1634239762bca16365db2eff7019d6684383ff50711a3ec791174ad7fc70f60e394a232c6971a55e'
        }
    ),
    HeaderCase(
        height=78192,
        hex='00000020a2adb636dec24cecba346825ec4f70023b8fdf92cd10b3c17f82c96824540200eb92612cc6bfe0001abe8873cd1d7a44fe64a587b4527f80ec7c6a00340a50e17031010000000000000000000000000000000000000000000000000000000000239dd75effff071f8f160a00000000000000000000000000000000000000000000000000bf05000063d9cdf9f906c72978574fa0a5c97ffbac46667f3e3b6a96557c8dd495b32ceff817373e7a8a149777f687c5a6cc4fa6ce1006befafb2394c6e0478633b2535309dac8771d47bba7c54d2059797effdaafbea0e0bbac0294575718550323e31d7e39c10e',
        data={
            'version': 536870912,
            'prev_block_hash': '0002542468c9827fc1b310cd92df8f3b02704fec256834baec4cc2de36b6ada2',
            'merkle_root': 'e1500a34006a7cec807f52b487a564fe447a1dcd7388be1a00e0bfc62c6192eb',
            'block_height': 78192,
            'reserved': '00000000000000000000000000000000000000000000000000000000',
            'timestamp': 1591188771,
            'bits': 0x1f07ffff,
            'nonce': '000005bf000000000000000000000000000000000000000000000000000a168f',
            'solution':'0ec1397e1de32303551857579402acbbe0a0beafdaff7e7959204dc5a7bb471d77c8da095353b2338647e0c69423fbfabe0610cea64fcca6c587f67797148a7a3e3717f8ef2cb395d48d7c55966a3b3e7f6646acfb7fc9a5a04f577829c706f9f9cdd963'
        }
    )
]

class Test_HeaderStorage(unittest.TestCase):

    def test_create_header_storage(self):
        db = HeaderStorage('./test1.db')
        self.assertTrue(os.path.exists('./test1.db'))
        shutil.rmtree('./test1.db')

    def test_save_block(self):
        db = HeaderStorage('./test2.db')

        db.save_header(HEADER_TEST_CASES[0].data)
        self.assertEqual(HEADER_TEST_CASES[0].hex, bh2u(db.db.Get(to_bytes(str(HEADER_TEST_CASES[0].height)))))

        db.save_header(HEADER_TEST_CASES[1].data)
        self.assertEqual(HEADER_TEST_CASES[1].hex, bh2u(db.db.Get(to_bytes(str(HEADER_TEST_CASES[1].height)))))

        db.save_header(HEADER_TEST_CASES[2].data)
        self.assertEqual(HEADER_TEST_CASES[2].hex, bh2u(db.db.Get(to_bytes(str(HEADER_TEST_CASES[2].height)))))
        
        shutil.rmtree('./test2.db')

    def test_read_header(self):
        db = HeaderStorage('./test3.db')

        db.save_header(HEADER_TEST_CASES[0].data)
        self.assertEqual(db.read_header(HEADER_TEST_CASES[0].height)['block_height'], HEADER_TEST_CASES[0].height)

        shutil.rmtree('./test3.db')

    def test_save_header_chunk(self):
        pass

    def test_read_header_chunk(self):
        pass


if __name__ == '__main__':
    unittest.main()
