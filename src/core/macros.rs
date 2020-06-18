#[macro_export]
macro_rules! string_vec {
        ($($x:expr),*) => (vec![$($x.to_string()),*]);
    }

#[macro_export]
macro_rules! string {
        ($s:expr) => {$s.to_string()};
    }

#[macro_export]
macro_rules! hash {
        () => {std::collections::HashMap::new()};
        ($($key:expr => $value:expr,)*) =>
            {  hash!($($key => $value),*) };
        ($($key:expr => $value:expr),* ) => {
            {
                let mut _map = std::collections::HashMap::new();
                $(
                    _map.insert($key, $value);
                )*
               _map
           }
       };
    }