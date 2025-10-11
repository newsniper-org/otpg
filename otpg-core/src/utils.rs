use creusot_contracts::trusted;


#[trusted]
#[inline]
pub(crate) fn flatten<const N: usize>(inputs: [&[u8]; N]) -> Vec<u8> {
    inputs.concat()
}

