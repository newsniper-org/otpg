use creusot_contracts::trusted;


#[trusted]
#[inline(always)]
pub(crate) fn flatten<const N: usize>(inputs: [&[u8]; N]) -> Vec<u8> {
    crate::creusot_utils::concat(inputs)
}

