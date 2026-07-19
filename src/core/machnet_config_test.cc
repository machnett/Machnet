/**
 * @file machnet_config_test.cc
 *
 * Unit tests for MachnetConfigProcessor, in particular the DPDK EAL option
 * generation for PCIe- vs. vdev-backed (e.g. net_tap) interfaces.
 *
 * These tests do not initialize DPDK EAL, so they need neither hugepages nor
 * elevated privileges.
 */
#include "machnet_config.h"

#include <gtest/gtest.h>

#include <fstream>
#include <string>

namespace {

// Writes `contents` to a unique temp file and returns its path.
std::string WriteTempConfig(const std::string &name,
                            const std::string &contents) {
  const std::string path = testing::TempDir() + "/machnet_cfg_" + name + ".json";
  std::ofstream out(path);
  out << contents;
  out.close();
  return path;
}

bool Contains(const std::string &haystack, const std::string &needle) {
  return haystack.find(needle) != std::string::npos;
}

// A vdev-backed interface should: parse the "vdev" key, carry no PCIe address,
// and cause GetEalOpts() to emit "--vdev <spec>" together with "--no-pci".
TEST(MachnetConfigTest, VdevInterfaceEalOpts) {
  const std::string cfg = R"({
    "machnet_config": {
      "02:00:00:00:00:01": {
        "ip": "10.0.0.1",
        "vdev": "net_tap0,iface=mtap0,mac=02:00:00:00:00:01"
      }
    }
  })";
  const std::string path = WriteTempConfig("vdev", cfg);

  juggler::MachnetConfigProcessor config(path);

  ASSERT_EQ(config.interfaces_config().size(), 1u);
  const auto &iface = *config.interfaces_config().begin();
  EXPECT_EQ(iface.vdev(), "net_tap0,iface=mtap0,mac=02:00:00:00:00:01");
  // A vdev interface must not carry a PCIe address (no sysfs discovery).
  EXPECT_EQ(iface.pcie_addr(), "");

  const std::string opts = config.GetEalOpts().ToString();
  EXPECT_TRUE(Contains(opts, "--vdev")) << opts;
  EXPECT_TRUE(Contains(opts, "net_tap0,iface=mtap0,mac=02:00:00:00:00:01"))
      << opts;
  EXPECT_TRUE(Contains(opts, "--no-pci")) << opts;
  // A vdev interface must not be added to the PCIe allowlist.
  EXPECT_FALSE(Contains(opts, "-a ")) << opts;

  std::remove(path.c_str());
}

// A PCIe-backed interface should emit "-a <addr>" and must NOT disable PCIe
// probing (no "--no-pci") nor create a vdev.
TEST(MachnetConfigTest, PcieInterfaceEalOpts) {
  const std::string cfg = R"({
    "machnet_config": {
      "02:00:00:00:00:01": {
        "ip": "10.0.0.1",
        "pcie": "0000:00:08.0"
      }
    }
  })";
  const std::string path = WriteTempConfig("pcie", cfg);

  juggler::MachnetConfigProcessor config(path);

  ASSERT_EQ(config.interfaces_config().size(), 1u);
  const auto &iface = *config.interfaces_config().begin();
  EXPECT_EQ(iface.pcie_addr(), "0000:00:08.0");
  EXPECT_EQ(iface.vdev(), "");

  const std::string opts = config.GetEalOpts().ToString();
  EXPECT_TRUE(Contains(opts, "-a 0000:00:08.0")) << opts;
  EXPECT_FALSE(Contains(opts, "--no-pci")) << opts;
  EXPECT_FALSE(Contains(opts, "--vdev")) << opts;

  std::remove(path.c_str());
}

}  // namespace

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
