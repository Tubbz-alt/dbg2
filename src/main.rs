use hwio::Mmio;
use std::{fs, io, ptr, slice, str};
use std::io::{Read, Seek, SeekFrom};

use crate::uart_16550::SerialPort;
mod uart_16550;

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct GenericAddress {
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct Dbg2 {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: [u8; 4],
    pub creator_revision: u32,
    pub device_offset: u32,
    pub device_count: u32,
}

impl Dbg2 {
    pub fn devices(&self) -> &[Dbg2Device] {
        unsafe {
            let self_addr = self as *const Self as usize;
            slice::from_raw_parts(
                (self_addr + self.device_offset as usize) as *const Dbg2Device,
                self.device_count as usize
            )
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(packed)]
pub struct Dbg2Device {
    pub revision: u8,
    pub length: u16,
    pub registers: u8,
    pub string_length: u16,
    pub string_offset: u16,
    pub oem_data_length: u16,
    pub oem_data_offset: u16,
    pub port_type: u16,
    pub port_subtype: u16,
    _reserved: u16,
    pub register_offset: u16,
    pub register_size_offset: u16,
}

impl Dbg2Device {
    pub fn string(&self) -> &[u8] {
        unsafe {
            let self_addr = self as *const Self as usize;
            slice::from_raw_parts(
                (self_addr + self.string_offset as usize) as *const u8,
                self.string_length as usize
            )
        }
    }

    pub fn registers(&self) -> (&[GenericAddress], &[u32]) {
        unsafe {
            let self_addr = self as *const Self as usize;
            (
                slice::from_raw_parts(
                    (self_addr + self.register_offset as usize) as *const GenericAddress,
                    self.registers as usize
                ),
                slice::from_raw_parts(
                    (self_addr + self.register_size_offset as usize) as *const u32,
                    self.registers as usize
                )
            )
        }
    }
}

fn main() -> io::Result<()> {
    let data = fs::read("/sys/firmware/acpi/tables/DBG2")?;

    let dbg2 = unsafe { &*(data.as_ptr() as *const Dbg2) };
    println!("{:#?}", dbg2);

    let mut port_addresses = Vec::new();

    for device in dbg2.devices() {
        println!("Device: {:?}", str::from_utf8(device.string()).map(|x| x.trim_matches('\0')));
        println!("{:#?}", device);
        let (registers, register_sizes) = device.registers();
        for i in 0..registers.len() {
            let register = registers[i];
            let register_size = register_sizes[i];
            println!("Register {}: {:x?}, {}", i, register, register_size);
            if device.port_type == 0x8000 && device.port_subtype == 0x0000 {
                if register.address_space == 0 {
                    println!("Adding MMIO port at {:#x}, {}", register.address, register_size);
                    port_addresses.push((register.address, register_size));
                } else {
                    println!("Ignoring unsupported port address space {:#x}", register.address_space);
                }
            } else {
                println!("Ignoring unsupported port type {:#x}, {:#x}", device.port_type, device.port_subtype);
            }
        }
    }

    if ! port_addresses.is_empty() {
        let memfd = unsafe {
            libc::open(
                b"/dev/mem\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_SYNC
            )
        };
        if memfd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ports = Vec::new();
        for (physical_address, size) in port_addresses {
            let address = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    size as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    memfd,
                    physical_address as libc::off_t
                )
            };
            if address == libc::MAP_FAILED {
                //TODO: Also unmap previous mappings
                unsafe { libc::close(memfd) };
                return Err(io::Error::last_os_error());
            }
            ports.push(unsafe {
                SerialPort::<Mmio<u8>>::new(address as usize)
            });
        }

        unsafe { libc::close(memfd) };

        let mut log = fs::File::open("/dev/kmsg")?;

        log.seek(SeekFrom::End(0))?;

        let mut print = |buf: &[u8]| {
            println!("{}", unsafe { str::from_utf8_unchecked(buf) });
            for port in &mut ports {
                port.init();
                port.write(buf);
                port.write(b"\n");
            }
        };

        print(b"Waiting for kernel messages...");

        let mut buf = [0; 4096];
        loop {
            let count = log.read(&mut buf)?;
            print(&buf[..count]);
        }

        //TODO: Also unmap previous mappings
    } else {
        println!("No supported ports found");
    }

    Ok(())
}
