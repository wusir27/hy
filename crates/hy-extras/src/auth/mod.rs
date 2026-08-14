//! password / userpass / HTTP / command authenticators.

mod command;
mod http;
mod password;
mod userpass;

pub use command::CommandAuth;
pub use http::HttpAuth;
pub use password::Password;
pub use userpass::UserPass;

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}
