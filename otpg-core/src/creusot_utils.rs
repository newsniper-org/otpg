use creusot_contracts::{logic::Mapping, *};


#[logic]
pub fn is_ok<T, E>(r: Result<T, E>) -> bool {
    match r {
        Ok(_) => true,
        Err(_) => false
    }
}

#[logic]
pub fn eq_if_ok<T: PartialEq, E>(a: Result<T, E>, b: T) -> bool {
    match a {
        Ok(a_inner) => a_inner == b,
        Err(_) => false
    }
}

#[logic]
pub fn select_left_if_ok<A, B, C, E>(r: Result<(A, B), E>, f: Mapping<A, C>) -> Result<C, E> {
    match r {
        Ok((a, _)) => Ok(f.get(a)),
        Err(e) => Err(e)
    }
}

#[logic]
pub fn select_right_if_ok<A, B, C, E>(r: Result<(A, B), E>, f: Mapping<B, C>) -> Result<C, E> {
    match r {
        Ok((_, b)) => Ok(f.get(b)),
        Err(e) => Err(e)
    }
}

pub enum OptionalOrdering {
    Less,
    Equal,
    Greater,
    Incomparable
}

#[logic]
pub const fn cmp_if_ok<T: OrdLogic, E>(a: Result<T, E>, b: T) -> OptionalOrdering {
    match a {
        Ok(a_inner) => if a_inner > b {
            OptionalOrdering::Greater
        } else if a_inner < b {
            OptionalOrdering::Less
        } else {
            OptionalOrdering::Equal
        },
        Err(_) => OptionalOrdering::Incomparable
    }
}

#[logic]
pub const fn has_any_item<T, E>(r: Result<Vec<T>, E>) -> bool {
    match r {
        Ok(v) => greater_than_zero_length(pearlite! { v@ }),
        Err(_) => false
    }
}

#[logic]
const fn greater_than_zero_length<T>(v: Seq<T>) -> bool {
    v.len() > 0
}

#[logic]
pub const fn fmap_result<A, B, E>(input: Result<A, E>, fmap: Mapping<A, B>) -> Result<B, E> {
    match input {
        Ok(a) => Ok(fmap.get(a)),
        Err(e) => Err(e)
    }
}

#[derive(::std::clone::Clone, ::std::marker::Copy)]
pub struct IntSumWrapper(pub Int);

impl IntSumWrapper {
    #[logic]
    fn sum(iter: Seq<Int>) -> Int {
        let result: Self = Self(0).sum_partial(iter,0,iter.len());
        result.0
    }

    #[logic]
    fn sum_partial(self, iter: Seq<Int>, curr_idx: Int, upper_bound: Int) -> Self {
        let inner_bound: Int = if upper_bound <= iter.len() {
            upper_bound
        } else {
            iter.len()
        };
        let result = if curr_idx < inner_bound {
            Self(self.0 + iter[curr_idx]).sum_partial(iter, curr_idx + 1, inner_bound)
        } else {
            self
        };
        result
    }
}

#[logic]
pub const fn get_sum(inputs: Seq<Int>) -> Int {
    IntSumWrapper::sum(inputs)
}

#[logic]
pub const fn get_sum_of_len(inputs: Seq<&[u8]>) -> Int {
    let seq_of_len = inputs.map(|s: &[u8]| pearlite! { s@.len() } );
    get_sum(seq_of_len)  
}


#[ensures(
    result@.len() == get_sum_of_len(inputs@)
)]
#[trusted]
pub fn concat<const N: usize>(inputs: [&[u8]; N]) -> Vec<u8> {
    inputs.concat()
}

#[logic]
pub const fn get_size_of_mat<const N: usize>(inputs: Seq<[u8; N]>) -> Int {
    let seq_of_len = inputs.map(|s: [u8; N]| pearlite! { s@.len() } );
    get_sum(seq_of_len)  
}

#[ensures(
    result@.len() == get_size_of_mat(inputs@)
)]
#[trusted]
pub fn concat_mat<const N: usize>(inputs: &[[u8; N]]) -> Vec<u8> {
    inputs.concat()
}