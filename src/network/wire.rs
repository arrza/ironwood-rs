use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use integer_encoding::VarInt;

use crate::types::PeerPort;

#[derive(Clone, PartialEq)]
pub enum Wire {
    Dummy = 0, // unused
    ProtoTree,
    ProtoDHTBootstrap,
    ProtoDHTBootstrapAck,
    ProtoDHTSetup,
    ProtoDHTTeardown,
    ProtoPathNotify,
    ProtoPathLookup,
    ProtoPathResponse,
    DHTTraffic,
    PathTraffic,
}

impl Into<u8> for Wire {
    fn into(self) -> u8 {
        self as u8
    }
}

impl From<u8> for Wire {
    fn from(value: u8) -> Self {
        match value {
            0 => Wire::Dummy,
            1 => Wire::ProtoTree,
            2 => Wire::ProtoDHTBootstrap,
            3 => Wire::ProtoDHTBootstrapAck,
            4 => Wire::ProtoDHTSetup,
            5 => Wire::ProtoDHTTeardown,
            6 => Wire::ProtoPathNotify,
            7 => Wire::ProtoPathLookup,
            8 => Wire::ProtoPathResponse,
            9 => Wire::DHTTraffic,
            10 => Wire::PathTraffic,
            _ => panic!("Invalid value for Wire enum"),
        }
    }
}

impl fmt::Display for Wire {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let printable = match *self {
            Wire::Dummy => "wireDummy",
            Wire::ProtoTree => "wireProtoTree",
            Wire::ProtoDHTBootstrap => "wireProtoDHTBootstrap",
            Wire::ProtoDHTBootstrapAck => "wireProtoDHTBootstrapAck",
            Wire::ProtoDHTSetup => "wireProtoDHTSetup",
            Wire::ProtoDHTTeardown => "wireProtoDHTTeardown",
            Wire::ProtoPathNotify => "wireProtoPathNotify",
            Wire::ProtoPathLookup => "wireProtoPathLookup",
            Wire::ProtoPathResponse => "wireProtoPathResponse",
            Wire::DHTTraffic => "wireDHTTraffic",
            Wire::PathTraffic => "wirePathTraffic",
        };
        write!(f, "{}", printable)
    }
}

// TODO? proper packet types for out-of-band, instead of embedding into ordinary traffic
#[derive(Debug)]
pub enum WireTraffic {
    Dummy = 0,
    Standard = 1,
    OutOfBand = 2,
}

impl fmt::Display for WireTraffic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<u8> for WireTraffic {
    fn from(num: u8) -> Self {
        match num {
            0 => WireTraffic::Dummy,
            1 => WireTraffic::Standard,
            2 => WireTraffic::OutOfBand,
            _ => panic!("Invalid value"),
        }
    }
}

impl Into<u8> for WireTraffic {
    fn into(self) -> u8 {
        self as u8
    }
}

#[derive(Debug)]
pub struct WireDecodeError;

impl Display for WireDecodeError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Wire decode error")
    }
}

impl Error for WireDecodeError {}

pub trait Encode: Sized {
    fn encode(&self, out: &mut Vec<u8>);
}
pub trait Decode: Sized {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError>;
}

pub trait WireMessage: Encode + Decode + Display {
    // methods...
}

pub fn encode_path(path: &Vec<PeerPort>, out: &mut Vec<u8>) {
    // Encode path
    for &port in path {
        let port_encoded = port.encode_var_vec();
        out.extend_from_slice(&port_encoded);
    }
    // if path.last().is_none()
    // /*|| (path.last().unwrap() != &0u64)*/
    // {
    //     let port_encoded = 0.encode_var_vec();
    //     out.extend_from_slice(&port_encoded);
    // }
}
