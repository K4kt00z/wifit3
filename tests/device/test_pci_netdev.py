from pathlib import Path
from unittest.mock import MagicMock, patch

from wifang.device.manager import _pci_netdev_devices, devices, supported_ids, wlan_iface
from wifang.models.device_id import DeviceID
from wifang.setup.linux import SetupLinux


def test_pci_netdev_devices_enumerates_matching_cards(tmp_path: Path):
    net_dir = tmp_path / "sys_class_net"
    wlan_dir = net_dir / "wlp62s0"
    (wlan_dir / "wireless").mkdir(parents=True)
    dev_dir = wlan_dir / "device"
    dev_dir.mkdir(parents=True)
    (dev_dir / "vendor").write_text("0x14c3\n")
    (dev_dir / "device").write_text("0x7922\n")

    # Mock subsystem symlink pointing to /sys/bus/pci
    subsys_target = tmp_path / "pci"
    subsys_target.mkdir()
    (dev_dir / "subsystem").symlink_to(subsys_target)

    smap = supported_ids()
    found = _pci_netdev_devices(smap, sysfs_net=net_dir)

    assert len(found) == 1
    dev = found[0]
    assert dev.chipset == "MT7922"
    assert dev.vid == 0x14C3
    assert dev.pid == 0x7922
    assert dev.bus == "pci"
    assert dev.extras["iface"] == "wlp62s0"
    assert dev.extras["bus_type"] == "pci"
    # The iface lives in extras (and so drives .locator); it is no longer inlined into product_name.
    assert dev.locator == "wlp62s0"
    assert "(wlp62s0)" not in (dev.product_name or "")


def test_wlan_iface_constructs_netdev_driver():
    dev_id = DeviceID(
        vid=0x14C3,
        pid=0x7922,
        chipset="MT7922",
        vendor="MediaTek",
        product_name="MT7922 802.11ax PCIe (wlp62s0)",
        bus="pci",
        address="0000:3e:00.0",
        extras={"iface": "wlp62s0", "bus_type": "pci"},
    )
    iface = wlan_iface(dev_id, name="wlan_pci0")
    assert iface is not None
    assert iface.name == "wlan_pci0"
    assert iface.chipset == "MT7922"
    assert iface.bus == "pci"
    from wifang.chips.netdev.driver import LinuxNetdevDriver
    assert isinstance(iface.driver, LinuxNetdevDriver)


def test_pci_card_does_not_require_setup():
    setup = SetupLinux()
    dev_id = DeviceID(
        vid=0x14C3,
        pid=0x7922,
        chipset="MT7922",
        vendor="MediaTek",
        bus="pci",
        address="0000:3e:00.0",
        extras={"iface": "wlp62s0", "bus_type": "pci"},
    )
    assert setup.requires_setup(dev_id) is False


def test_devices_includes_both_usb_and_pci():
    mock_usb_dev = DeviceID(
        vid=0x0E8D,
        pid=0x7961,
        chipset="MT7921AU",
        vendor="MediaTek",
        bus=1,
        address=2,
    )
    mock_pci_dev = DeviceID(
        vid=0x14C3,
        pid=0x7922,
        chipset="MT7922",
        vendor="MediaTek",
        bus="pci",
        address="0000:3e:00.0",
        extras={"iface": "wlp62s0", "bus_type": "pci"},
    )
    with patch("wifang.device.manager._bus_devices", return_value=[]):
        with patch("wifang.device.manager._pnp_only_devices", return_value=[mock_usb_dev]):
            with patch("wifang.device.manager._pci_netdev_devices", return_value=[mock_pci_dev]):
                all_devs = devices()
                assert mock_usb_dev in all_devs
                assert mock_pci_dev in all_devs


def test_usb_iface_names_maps_busnum_devnum_to_iface(tmp_path: Path):
    from wifang.device.manager import _usb_iface_names
    net_dir = tmp_path / "net"
    wlan = net_dir / "wlan0"
    (wlan / "wireless").mkdir(parents=True)
    usb_device = tmp_path / "usb" / "1-5"
    usb_iface = usb_device / "1-5:1.0"
    usb_iface.mkdir(parents=True)
    (usb_device / "busnum").write_text("1\n")
    (usb_device / "devnum").write_text("5\n")
    (wlan / "device").symlink_to(usb_iface)

    assert _usb_iface_names(sysfs_net=net_dir) == {(1, 5): "wlan0"}


def test_usb_iface_names_skips_a_device_without_busnum(tmp_path: Path):
    from wifang.device.manager import _usb_iface_names
    net_dir = tmp_path / "net"
    wlan = net_dir / "wlp62s0"
    (wlan / "wireless").mkdir(parents=True)
    pci_device = tmp_path / "pci" / "0000:3e:00.0"
    pci_device.mkdir(parents=True)
    (wlan / "device").symlink_to(pci_device)

    assert _usb_iface_names(sysfs_net=net_dir) == {}


def test_devices_attaches_kernel_iface_name_to_usb_card():
    from types import SimpleNamespace
    mock_usb = SimpleNamespace(idVendor=0x0E8D, idProduct=0x7961, bus=1, address=5)
    with patch("wifang.device.manager._require_backend", return_value=MagicMock()), \
         patch("wifang.device.manager._bus_devices", return_value=[mock_usb]), \
         patch("wifang.device.manager._pnp_only_devices", return_value=[]), \
         patch("wifang.device.manager._pci_netdev_devices", return_value=[]), \
         patch("wifang.device.manager._usb_iface_names", return_value={(1, 5): "wlan0"}):
        found = devices()

    usb = next(d for d in found if (d.vid, d.pid) == (0x0E8D, 0x7961))
    assert usb.extras["iface"] == "wlan0"
    assert usb.locator == "wlan0"
