use creusot_contracts::{ensures, trusted};


#[trusted]
#[inline(always)]
pub(crate) fn flatten<const N: usize>(inputs: [&[u8]; N]) -> Vec<u8> {
    crate::creusot_utils::concat(inputs)
}

#[ensures(
    ((a@.len() == b@.len()) && (forall<i: usize> i@ < a@.len() ==> a[i]@ == b[i]@)) == result
)]
#[trusted]
pub fn eq_bytes(a: &[u8], b: &[u8]) -> bool {
    a.iter().eq(b.iter())
}