# -*- mode: ruby -*-
# vi: set ft=ruby :

require "yaml"

root = File.expand_path(__dir__)
config_path = File.join(root, ENV.fetch("CONFIG_FILE", "config.yml"))
example_path = File.join(root, "config.example.yml")

def deep_merge(base, override)
  base.merge(override) do |_key, old_value, new_value|
    old_value.is_a?(Hash) && new_value.is_a?(Hash) ? deep_merge(old_value, new_value) : new_value
  end
end

base = YAML.load_file(example_path) || {}
user = File.exist?(config_path) ? (YAML.load_file(config_path) || {}) : {}
rr = deep_merge(base, user)
win = rr.fetch("windows")
network = rr.fetch("network")
virtio = win.fetch("virtio", {})

Vagrant.configure("2") do |config|
  config.vm.define win.fetch("vm_name", "reuserupture-dc"), primary: true do |dc|
    dc.vm.box = win.fetch("vagrant_box", "").to_s.empty? ? "generic/windows2022" : win.fetch("vagrant_box")
    dc.vm.hostname = win.fetch("hostname", "DC01")
    dc.vm.communicator = "winrm"
    dc.winrm.username = win.fetch("username", "Administrator")
    dc.winrm.password = rr.fetch("active_directory").fetch("administrator_password")
    dc.winrm.transport = :ssl
    dc.winrm.ssl_peer_verification = false
    dc.vm.network "private_network", ip: win.fetch("ip", "192.168.56.10")

    dc.vm.provider :libvirt do |libvirt|
      libvirt.default_prefix = ""
      libvirt.memory = win.fetch("memory_mb", 8192).to_s == "auto" ? 8192 : win.fetch("memory_mb")
      libvirt.cpus = win.fetch("vcpus", 4).to_s == "auto" ? 4 : win.fetch("vcpus")
      libvirt.storage_pool_name = "default"
      libvirt.disk_bus = virtio.fetch("enabled", true) ? "virtio" : "sata"
      libvirt.nic_model_type = virtio.fetch("enabled", true) ? "virtio" : "e1000e"
      libvirt.management_network_name = network.fetch("name", "reuserupture-net")

      windows_iso = File.expand_path(win.fetch("iso_path"), root)
      if File.exist?(windows_iso)
        libvirt.storage :file, device: :cdrom, path: windows_iso
      end

      virtio_iso = File.expand_path(virtio.fetch("iso_path", "iso/virtio-win.iso"), root)
      if virtio.fetch("enabled", true) && File.exist?(virtio_iso)
        libvirt.storage :file, device: :cdrom, path: virtio_iso
      end
    end
  end
end
