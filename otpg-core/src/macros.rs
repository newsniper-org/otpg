#[macro_export]
macro_rules! define_with_serde {
    ( $( $item1:item )* ) => {
        // 받은 아이템 각각에 대해 루프를 돌며 코드를 생성합니다.
        $(
            // 각 아이템에 대해 동일한 cfg_attr 로직을 적용합니다.
            #[cfg(all(not(hax), feature = "serde"))]
            $item1
        )*
    };
}

#[macro_export]
macro_rules! define_without_serde {
    ( $( $item:item )* ) => {
        // 받은 아이템 각각에 대해 루프를 돌며 코드를 생성합니다.
        $(
            // 각 아이템에 대해 동일한 cfg_attr 로직을 적용합니다.
            #[cfg(any(hax, not(feature = "serde")))]
            $item
        )*
    };
}

#[macro_export]
macro_rules! optional_serde_derive {
    // $(...)* 패턴을 사용하여 여러 아이템을 한 번에 받습니다.
    ( $( $item:item )* ) => {
        // 받은 아이템 각각에 대해 루프를 돌며 코드를 생성합니다.
        $(
            // 각 아이템에 대해 동일한 cfg_attr 로직을 적용합니다.
            #[cfg_attr(all(not(hax), feature = "serde"), derive(serde::Serialize, serde::Deserialize))]
            $item
        )*
    };
}

#[macro_export]
macro_rules! conditional_serde {
    // `let` 바인딩을 위한 매크로 규칙
    (let $var:ident = $serde:expr, or_else_hax $noserde:expr) => {
        #[cfg(all(not(hax), feature = "serde"))]
        let $var = $serde;

        // hax 환경이거나 serde 기능이 비활성화된 경우, noserde 표현식을 사용합니다.
        #[cfg(any(hax, not(feature = "serde")))]
        let $var = $noserde;
    };
}