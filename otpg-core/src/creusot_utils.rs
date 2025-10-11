use creusot_contracts::*;


#[logic]
pub fn is_ok<T, E>(r: Result<T, E>) -> bool {
    match r {
        Ok(_) => true,
        Err(_) => false
    }
}

#[logic]
pub fn cmp_if_ok<T: PartialEq, E>(a: Result<T, E>, b: T) -> bool {
    match a {
        Ok(a_inner) => a_inner == b,
        Err(_) => false
    }
}


pub fn concat_bytes(inputs: &[&[u8]]) -> Vec<u8> {
    inputs.concat()
}

pub fn fmap_result<A, B, E, F: Fn(A) -> B>(input: Result<A, E>, fmap: F) -> Result<B, E> {
    match input {
        Ok(a) => Ok(fmap(a)),
        Err(e) => Err(e)
    }
}