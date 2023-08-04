use crate::ofp_header::OfpHeader;
use crate::ofp_header::OfpVendorHeader;

/// OpenFlow Message
///
/// Version-agnostic API for handling OpenFlow messages at the byte-buffer level.
pub trait OfpMessage {
    /// Return the byte-size of an `OfpMessage`.
    fn size_of(_: &Self) -> usize;
    /// Create an `OfpHeader` for the given transaction id and OpenFlow message.
    fn header_of(_: u32, _: &Self) -> OfpHeader;
    /// Create an `OfpHeader` for the given transaction id and OpenFlow message.
    fn vendor_header_of(_: u32, _: &Self) -> OfpVendorHeader;
    /// Return a marshaled buffer containing an OpenFlow header and the message `msg`.
    fn marshal(_: u32, _: Self) -> Vec<u8>;
    /// Returns a pair `(u32, OfpMessage)` of the transaction id and OpenFlow message parsed from
    /// the given OpenFlow header `header`, and buffer `buf`.
    fn parse(_: &OfpHeader, _: &[u8]) -> (u32, Self);
    fn parse_vendor(_: &OfpVendorHeader, _: &[u8]) -> (u32, Self);
}
