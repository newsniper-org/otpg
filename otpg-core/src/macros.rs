#[macro_export]
macro_rules! optional_serde_derive {
    // $(...)* 패턴을 사용하여 여러 아이템을 한 번에 받습니다.
    ( $cfg:meta ; $( $item:item )* ) => {
        // 받은 아이템 각각에 대해 루프를 돌며 코드를 생성합니다.
        $(
            // 각 아이템에 대해 동일한 cfg_attr 로직을 적용합니다.
            #[cfg_attr($cfg, derive(serde::Serialize, serde::Deserialize))]
            $item
        )*
    };
}

#[macro_export]
macro_rules! cfg_match {
    // `let` 바인딩을 위한 매크로 규칙
    ( let $var:ident = { $( $cfg:meta => $expr:expr ),* } ) => {
        $(
            #[cfg($cfg)]
            let $var = $expr;
        )*
    };
}


#[cfg(not(creusot))]
#[macro_export]
macro_rules! bytes_concat {
    ( $( $expr:expr ),+ ) => [
        [$(
            $expr.as_slice()
        ),+].concat()
    ];
}

#[cfg(creusot)]
#[macro_export]
macro_rules! bytes_concat {
    ( $( $expr:expr ),+ ) => [
        crate::creusot_utils::concat([$(
            &$expr
        ),+])
    ];
}