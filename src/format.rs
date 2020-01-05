//! The age message format.

use std::io::{self, Read, Write};

use crate::primitives::HmacWriter;

pub(crate) mod scrypt;
pub(crate) mod ssh_ed25519;
#[cfg(feature = "unstable")]
pub(crate) mod ssh_rsa;
pub(crate) mod x25519;

const V1_MAGIC: &[u8] = b"age-encryption.org/v1";
const RECIPIENT_TAG: &[u8] = b"-> ";
const MAC_TAG: &[u8] = b"---";

#[derive(Debug)]
pub(crate) enum UnknownArgument {
    /// Base64-encoded data.
    Encoded(Vec<u8>),
    /// A decimal integer.
    Numeric(u64),
}

#[derive(Debug)]
pub(crate) enum RecipientLine {
    X25519(x25519::RecipientLine),
    Scrypt(scrypt::RecipientLine),
    #[cfg(feature = "unstable")]
    SshRsa(ssh_rsa::RecipientLine),
    SshEd25519(ssh_ed25519::RecipientLine),
    Unknown {
        tag: String,
        args: Vec<UnknownArgument>,
        body: Vec<u8>,
    },
}

impl From<x25519::RecipientLine> for RecipientLine {
    fn from(line: x25519::RecipientLine) -> Self {
        RecipientLine::X25519(line)
    }
}

impl From<scrypt::RecipientLine> for RecipientLine {
    fn from(line: scrypt::RecipientLine) -> Self {
        RecipientLine::Scrypt(line)
    }
}

#[cfg(feature = "unstable")]
impl From<ssh_rsa::RecipientLine> for RecipientLine {
    fn from(line: ssh_rsa::RecipientLine) -> Self {
        RecipientLine::SshRsa(line)
    }
}

impl From<ssh_ed25519::RecipientLine> for RecipientLine {
    fn from(line: ssh_ed25519::RecipientLine) -> Self {
        RecipientLine::SshEd25519(line)
    }
}

pub struct Header {
    pub(crate) recipients: Vec<RecipientLine>,
    pub(crate) mac: [u8; 32],
}

impl Header {
    pub(crate) fn new(recipients: Vec<RecipientLine>, mac_key: [u8; 32]) -> Self {
        let mut header = Header {
            recipients,
            mac: [0; 32],
        };

        let mut mac = HmacWriter::new(mac_key);
        cookie_factory::gen(write::header_minus_mac(&header), &mut mac)
            .expect("can serialize Header into HmacWriter");
        header.mac.copy_from_slice(mac.result().code().as_slice());

        header
    }

    pub(crate) fn verify_mac(&self, mac_key: [u8; 32]) -> Result<(), hmac::crypto_mac::MacError> {
        let mut mac = HmacWriter::new(mac_key);
        cookie_factory::gen(write::header_minus_mac(self), &mut mac)
            .expect("can serialize Header into HmacWriter");
        mac.verify(&self.mac)
    }

    pub(crate) fn read<R: Read>(mut input: R) -> io::Result<Self> {
        let mut data = vec![];
        loop {
            match read::header(&data) {
                Ok((_, header)) => break Ok(header),
                Err(nom::Err::Incomplete(nom::Needed::Size(n))) => {
                    // Read the needed additional bytes. We need to be careful how the
                    // parser is constructed, because if we read more than we need, the
                    // remainder of the input will be truncated.
                    let m = data.len();
                    data.resize(m + n, 0);
                    input.read_exact(&mut data[m..m + n])?;
                }
                Err(_) => {
                    break Err(io::Error::new(io::ErrorKind::InvalidData, "invalid header"));
                }
            }
        }
    }

    pub(crate) fn write<W: Write>(&self, mut output: W) -> io::Result<()> {
        cookie_factory::gen(write::header(self), &mut output)
            .map(|_| ())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to write header: {}", e),
                )
            })
    }
}

mod read {
    use nom::{
        branch::alt,
        bytes::streaming::{tag, take_while1},
        character::{
            is_alphanumeric,
            streaming::{digit1, newline},
        },
        combinator::{map, map_res},
        multi::separated_nonempty_list,
        sequence::{pair, preceded, separated_pair, terminated},
        IResult,
    };

    use super::*;
    use crate::util::read::{data_while_encoded, encoded_data, wrapped_encoded_data};

    /// Parses an age recipient line tag.
    ///
    /// Valid tags are alphanumeric hyphen-separated words.
    fn recipient_tag(input: &[u8]) -> IResult<&[u8], String> {
        map_res(
            take_while1(|chr: u8| is_alphanumeric(chr) || chr == b'-'),
            |tag| std::str::from_utf8(tag).map(String::from),
        )(input)
    }

    /// Parses an age recipient line argument.
    ///
    /// Valid arguments are:
    /// - Base64-encoded data
    /// - Decimal integers
    fn unknown_argument(input: &[u8]) -> IResult<&[u8], UnknownArgument> {
        alt((
            map(data_while_encoded, UnknownArgument::Encoded),
            map(digit1, |digits| {
                UnknownArgument::Numeric(
                    u64::from_str_radix(
                        std::str::from_utf8(digits).expect("digit1 only returns digits"),
                        10,
                    )
                    .expect("digit1 only returns digits"),
                )
            }),
        ))(input)
    }

    fn unknown_recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        map(
            separated_pair(
                separated_pair(
                    recipient_tag,
                    tag(" "),
                    separated_nonempty_list(tag(" "), unknown_argument),
                ),
                newline,
                wrapped_encoded_data,
            ),
            |((tag, args), body)| RecipientLine::Unknown { tag, args, body },
        )(input)
    }

    fn recipient_line(input: &[u8]) -> IResult<&[u8], RecipientLine> {
        preceded(
            tag(RECIPIENT_TAG),
            alt((
                map(x25519::read::recipient_line, RecipientLine::from),
                map(scrypt::read::recipient_line, RecipientLine::from),
                #[cfg(feature = "unstable")]
                map(ssh_rsa::read::recipient_line, RecipientLine::from),
                map(ssh_ed25519::read::recipient_line, RecipientLine::from),
                unknown_recipient_line,
            )),
        )(input)
    }

    pub(super) fn header(input: &[u8]) -> IResult<&[u8], Header> {
        preceded(
            pair(tag(V1_MAGIC), newline),
            map(
                pair(
                    terminated(separated_nonempty_list(newline, recipient_line), newline),
                    preceded(
                        pair(tag(MAC_TAG), tag(b" ")),
                        terminated(encoded_data(32, [0; 32]), newline),
                    ),
                ),
                |(recipients, mac)| Header { recipients, mac },
            ),
        )(input)
    }
}

mod write {
    use cookie_factory::{
        combinator::{slice, string},
        multi::separated_list,
        sequence::tuple,
        SerializeFn, WriteContext,
    };
    use std::io::Write;

    use super::*;
    use crate::util::write::{encoded_data, wrapped_encoded_data};

    fn unknown_argument<'a, W: 'a + Write>(arg: &'a UnknownArgument) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| match arg {
            UnknownArgument::Encoded(data) => encoded_data(data)(w),
            UnknownArgument::Numeric(n) => string(format!("{}", n))(w),
        }
    }

    fn unknown_recipient_line<'a, W: 'a + Write>(
        tag: &'a str,
        args: &'a [UnknownArgument],
        body: &'a [u8],
    ) -> impl SerializeFn<W> + 'a {
        tuple((
            string(tag),
            string(" "),
            separated_list(string(" "), args.iter().map(|arg| unknown_argument(arg))),
            string("\n"),
            wrapped_encoded_data(body),
        ))
    }

    fn recipient_line<'a, W: 'a + Write>(r: &'a RecipientLine) -> impl SerializeFn<W> + 'a {
        move |w: WriteContext<W>| {
            let out = slice(RECIPIENT_TAG)(w)?;
            match r {
                RecipientLine::X25519(r) => x25519::write::recipient_line(r)(out),
                RecipientLine::Scrypt(r) => scrypt::write::recipient_line(r)(out),
                #[cfg(feature = "unstable")]
                RecipientLine::SshRsa(r) => ssh_rsa::write::recipient_line(r)(out),
                RecipientLine::SshEd25519(r) => ssh_ed25519::write::recipient_line(r)(out),
                RecipientLine::Unknown { tag, args, body } => {
                    unknown_recipient_line(tag, args, body)(out)
                }
            }
        }
    }

    pub(super) fn header_minus_mac<'a, W: 'a + Write>(h: &'a Header) -> impl SerializeFn<W> + 'a {
        tuple((
            slice(V1_MAGIC),
            string("\n"),
            separated_list(
                string("\n"),
                h.recipients.iter().map(move |r| recipient_line(r)),
            ),
            string("\n"),
            slice(MAC_TAG),
        ))
    }

    pub(super) fn header<'a, W: 'a + Write>(h: &'a Header) -> impl SerializeFn<W> + 'a {
        tuple((
            header_minus_mac(h),
            string(" "),
            encoded_data(&h.mac),
            string("\n"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::Header;

    #[test]
    fn parse_header() {
        let test_header = "age-encryption.org/v1
-> X25519 CJM36AHmTbdHSuOQL+NESqyVQE75f2e610iRdLPEN20
C3ZAeY64NXS4QFrksLm3EGz+uPRyI0eQsWw7LWbbYig
-> X25519 ytazqsbmUnPwVWMVx0c1X9iUtGdY4yAB08UQTY2hNCI
N3pgrXkbIn/RrVt0T0G3sQr1wGWuclqKxTSWHSqGdkc
-> scrypt bBjlhJVYZeE4aqUdmtRHfw 15
ZV/AhotwSGqaPCU43cepl4WYUouAa17a3xpu4G2yi5k
-> ssh-rsa mhir0Q
xD7o4VEOu1t7KZQ1gDgq2FPzBEeSRqbnqvQEXdLRYy143BxR6oFxsUUJCRB0ErXA
mgmZq7tIm5ZyY89OmqZztOgG2tEB1TZvX3Q8oXESBuFjBBQkKaMLkaqh5GjcGRrZ
e5MmTXRdEyNPRl8qpystNZR1q2rEDUHSEJInVLW8OtvQRG8P303VpjnOUU53FSBw
yXxDtzxKxeloceFubn/HWGcR0mHU+1e9l39myQEUZjIoqFIELXvh9o6RUgYzaAI+
m/uPLMQdlIkiOOdbsrE6tFesRLZNHAYspeRKI9MJ++Xg9i7rutU34ZM+1BL6KgZf
J9FSm+GFHiVWpr1MfYCo/w
-> ssh-ed25519 BjH7FA RO+wV4kbbl4NtSmp56lQcfRdRp3dEFpdQmWkaoiw6lY
51eEu5Oo2JYAG7OU4oamH03FDRP18/GnzeCrY7Z+sa8
-> some-other-recipient mhir0Q BjH7FA 37
m/uPLMQdlIkiOOdbsrE6tFesRLZNHAYspeRKI9MJ++Xg9i7rutU34ZM+1BL6KgZf
J9FSm+GFHiVWpr1MfYCo/w
--- fgMiVLJHMlg9fW7CVG/hPS5EAU4Zeg19LyCP7SoH5nA
";
        let h = Header::read(test_header.as_bytes()).unwrap();
        let mut data = vec![];
        h.write(&mut data).unwrap();
        assert_eq!(std::str::from_utf8(&data), Ok(test_header));
    }
}
