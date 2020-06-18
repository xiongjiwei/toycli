fn error<S: Into<String>>(msg: S) -> ! {
    eprintln!("{}", msg.into());
    panic!()
}

struct Token {
    t: String
}

impl Token {
    fn is_flag(&self) -> bool {
        self.t.starts_with("-") || self.t.starts_with("--")
    }

    fn origin(&self) -> String {
        self.t.clone()
    }
}

struct Lexer {
    tokens: Vec<Token>,
    index: usize,
}

impl Lexer {
    fn new(tokens: std::vec::Vec<Token>) -> Self {
        Self { tokens, index: 0 }
    }

    fn next(&mut self) {
        self.index += 1;
    }

    fn token(&self) -> &Token {
        &self.tokens[self.index]
    }

    fn end(&self) -> bool {
        self.index >= self.tokens.len()
    }
}

type ParseOptionMap = std::collections::HashMap<String, Vec<String>>;

#[derive(Default, Debug)]
struct ParserRet {
    name: String,
    cmd: String,
    args: Vec<String>,
    options: ParseOptionMap,
}

impl ParserRet {
    fn new() -> ParserRet {
        Self {
            ..Default::default()
        }
    }
}

struct Parser {
    lexer: Lexer,
    ret: ParserRet,
}

impl Parser {
    fn new(tokens: std::vec::Vec<Token>) -> Self {
        Self {
            lexer: Lexer::new(tokens),
            ret: ParserRet::new(),
        }
    }


    fn parse(args: std::vec::Vec<String>) -> Result<ParserRet, String> {
        let tokens = args.iter()
            .map(|arg| Token { t: arg.into() })
            .collect::<Vec<Token>>();
        let parser = Parser::new(tokens);
        Ok(parser)
            .and_then(Parser::parser_app_name)
            .and_then(Parser::parser_sub_command)
            .and_then(Parser::parser_arg)
            .and_then(Parser::parser_flag)
            .and_then(Parser::get)
    }

    fn parser_app_name(mut self) -> Result<Self, String> {
        self.ret.name = self.lexer.token().origin();
        self.lexer.next();
        Ok(self)
    }

    fn parser_sub_command(mut self) -> Result<Self, String> {
        if self.lexer.end() {
            return Err(string!("no command"));
        }

        self.ret.cmd = if self.lexer.token().is_flag() {
            string!("")
        } else {
            let cmd = self.lexer.token().origin();
            self.lexer.next();
            cmd
        };

        Ok(self)
    }

    fn parser_arg(mut self) -> Result<Self, String> {
        while !self.lexer.end() && !self.lexer.token().is_flag() {
            self.ret.args.push(self.lexer.token().origin());
            self.lexer.next();
        }

        Ok(self)
    }

    fn parser_flag(mut self) -> Result<Self, String> {
        while !self.lexer.end() {
            let flag = self.lexer.token().origin();
            let mut args = vec![];
            self.lexer.next();

            while !self.lexer.end() && !self.lexer.token().is_flag() {
                args.push(self.lexer.token().origin());
                self.lexer.next();
            }

            self.ret.options.insert(flag, args);
        }
        Ok(self)
    }

    fn get(self) -> Result<ParserRet, String> {
        Ok(self.ret)
    }
}

#[derive(Default)]
pub struct ArgMatches {
    name: String,
    args: Vec<String>,
    sub_command: std::collections::HashMap<String, ArgMatches>,
    options: ParseOptionMap,
}

impl ArgMatches {
    pub fn sub_command<S: Into<String>>(&self, cmd: S) -> Option<&Self> {
        self.sub_command.get(cmd.into().as_str())
    }

    pub fn value_of<S: Into<String>>(&self, s: S) -> Option<&Vec<String>> {
        self.options.get(s.into().as_str())
    }

    pub fn args(&self) -> &Vec<String> {
        &self.args
    }
}

/// `Args` represent options args constraint
#[derive(Default, Debug)]
pub struct Args {
    name: String,
    short: String,
    long: String,
    required: bool,
    conflict: std::collections::HashSet<String>,
    min_value: usize,
    max_value: usize,
}

impl Args {
    pub fn new<S: Into<String>>(name: S) -> Self {
        let n = name.into();
        Self {
            name: n.clone(),
            long: string!("--") + n.as_str(),
            ..Default::default()
        }
    }

    pub fn conflict_with<S: Into<String>>(mut self, conflict: S) -> Self {
        self.conflict.insert(conflict.into());
        self
    }

    pub fn conflict_with_all<S: Into<String>>(mut self, conflict: Vec<S>) -> Self {
        for s in conflict {
            self.conflict.insert(s.into());
        }
        self
    }

    pub fn arg_count(mut self, c: usize) -> Self {
        self.min_value = c;
        self.max_value = c;
        self
    }

    pub fn takes_value(mut self) -> Self {
        self.min_value = 1;
        self.max_value = 1;
        self
    }

    pub fn short(mut self, c: char) -> Self {
        self.short = string!("-");
        self.short.push(c);
        self
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }


    fn test(&self, options: &ParseOptionMap) -> bool {
        if !options.contains_key(self.name.as_str()) {
            return !self.required;
        }

        self.test_arg_count(options) &&
            self.test_conflict(options)
    }

    fn test_arg_count(&self, options: &ParseOptionMap) -> bool {
        let args = options.get(self.name.as_str()).unwrap();
        self.min_value <= args.len() && args.len() <= self.max_value
    }

    fn test_conflict(&self, options: &ParseOptionMap) -> bool {
        self.conflict.iter().all(|s| !options.contains_key(s))
    }
}

type OptionNameMap = std::collections::HashMap<String, String>;
type OptionMap = std::collections::HashMap<String, Args>;
type CommandMap = std::collections::HashMap<String, SubCommand>;

#[derive(Default, Debug)]
pub struct SubCommand {
    name: String,
    min_value: usize,
    max_value: usize,
    flag_name_map: OptionNameMap,
    options: OptionMap,
}

impl SubCommand {
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn arg_count(mut self, c: usize) -> Self {
        self.min_value = c;
        self.max_value = c;
        self
    }

    pub fn takes_value(mut self) -> Self {
        self.min_value = 1;
        self.max_value = 1;
        self
    }

    pub fn arg(mut self, arg: Args) -> Self {
        self.set_option(arg);
        self
    }

    fn set_option(&mut self, arg: Args) {
        self.set_flag_name_map(&arg);
        if self.options.contains_key(arg.name.as_str()) {
            error(format!("option {} dup", arg.name));
        }

        self.options.insert(arg.name.clone(), arg);
    }

    fn set_flag_name_map(&mut self, arg: &Args) {
        if self.flag_name_map.contains_key(arg.long.as_str()) {
            error(format!("dup long {}", arg.long));
        }

        self.flag_name_map.insert(arg.long.clone(), arg.name.clone());
        if !arg.short.is_empty() {
            if self.flag_name_map.contains_key(arg.short.as_str()) {
                error(format!("dup short {}", arg.short));
            }

            self.flag_name_map.insert(arg.short.clone(), arg.name.clone());
        }
    }

    fn map_flag(&self, pr: &mut ParserRet) -> Result<&Self, String> {
        let copy_option = pr.options.clone();
        pr.options.clear();
        for option in copy_option {
            let op = match self.flag_name_map.get(option.0.as_str()) {
                Some(op) => op,
                None => return Err(format!("no option {}", option.0)),
            };
            if pr.options.contains_key(op) {
                return Err(format!("option {} dup", op));
            }

            pr.options.insert(op.to_owned(), option.1);
        }
        Ok(self)
    }

    fn verification_arg(&self, parse: &ParserRet) -> Result<&Self, String> {
        if self.min_value <= parse.args.len() && parse.args.len() <= self.max_value {
            Ok(self)
        } else {
            Err(string!("args not match"))
        }
    }

    fn verification_options(&self, parse: &ParserRet) -> Result<&Self, String> {
        if parse.options.keys().any(|key| !self.options.contains_key(key)) {
            return Err(format!("option invalid"));
        }
        if self.options.values().any(|value| !value.test(&parse.options)) {
            return Err(format!("option not qualify"));
        }
        Ok(self)
    }

    fn build_match(&self, parse: ParserRet) -> Result<ArgMatches, String> {
        let mut matches = ArgMatches::default();
        matches.name = parse.cmd;
        matches.args = parse.args;
        matches.options = parse.options;
        if !matches.name.is_empty() {
            let mut warp_matches = ArgMatches::default();
            warp_matches.sub_command.insert(matches.name.clone(), matches);
            return Ok(warp_matches);
        }
        Ok(matches)
    }
}

#[derive(Debug)]
pub struct Cli {
    name: String,
    commands: CommandMap,
}

impl Cli {
    pub fn new<S: Into<String>>(name: S) -> Self {
        let mut cli = Self { name: name.into(), commands: std::collections::HashMap::new() };
        let sub_command = SubCommand::default();
        cli.commands.insert(string!(""), sub_command);
        cli
    }

    pub fn get_matches(&self) -> ArgMatches {
        let from = std::env::args().collect::<Vec<String>>();
        self.get_matches_from(from).expect("command failed")
    }

    pub fn try_get_matches_from(&self, from: Vec<String>) -> Option<ArgMatches> {
        self.get_matches_from(from).ok()
    }

    fn get_matches_from(&self, from: Vec<String>) -> Result<ArgMatches, String> {
        let mut parse = ParserRet::default();
        Parser::parse(from)
            .and_then(|p| {
                parse = p;
                self.commands.get(parse.cmd.as_str()).ok_or(string!("no such command"))
            })
            .and_then(|cmd| cmd.map_flag(&mut parse))
            .and_then(|cmd| cmd.verification_arg(&parse))
            .and_then(|cmd| cmd.verification_options(&parse))
            .and_then(|cmd| cmd.build_match(parse))
    }

    pub fn subcommand(mut self, sub: SubCommand) -> Self {
        if self.commands.contains_key(sub.name.as_str()) {
            error(format!("sub command {} dup", sub.name));
        }

        self.commands.insert(sub.name.clone(), sub);
        self
    }

    pub fn arg(mut self, arg: Args) -> Self {
        self.commands.get_mut("").unwrap().set_option(arg);
        self
    }

    fn print_usage(&self) {}
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::option::Option::Some;

    use crate::core::cli::{ArgMatches, Args, Cli, Parser, SubCommand};

    #[test]
    fn test_parser() {
        struct T {
            input: Vec<String>,
            w_name: String,
            w_sub_command: String,
            w_args: Vec<String>,
            w_flags: HashMap<String, Vec<String>>,
        }

        let table = vec![
            T {
                input: string_vec!["cargo", "build", "-o", "p", "t"],
                w_name: string!("cargo"),
                w_sub_command: string!("build"),
                w_args: string_vec![],
                w_flags: hash! {
                    string!("-o") => string_vec!["p", "t"],
                },
            },
            T {
                input: string_vec!["git", "push", "origin", "-D", "course:course", "-v"],
                w_name: string!("git"),
                w_sub_command: string!("push"),
                w_args: string_vec!["origin"],
                w_flags: hash! {
                    string!("-D") => string_vec!["course:course"],
                    string!("-v") => string_vec![],
                },
            },
            T {
                input: string_vec!["like", "-s", "long", "t", "-f", "-k", "shut"],
                w_name: string!("like"),
                w_sub_command: string!(""),
                w_args: string_vec![],
                w_flags: hash! {
                    string!("-s") => string_vec!["long", "t"],
                    string!("-f") => string_vec![],
                    string!("-k") => string_vec!["shut"],
                },
            },
            T {
                input: string_vec!["kvs", "set", "key", "value"],
                w_name: string!("kvs"),
                w_sub_command: string!("set"),
                w_args: string_vec!["key", "value"],
                w_flags: hash! {},
            },
        ];

        for t in table {
            let ret = Parser::parse(t.input).unwrap();
            assert_eq!(t.w_name, ret.name);
            assert_eq!(t.w_sub_command, ret.cmd);
            assert_eq!(t.w_args, ret.args);
            assert_eq!(t.w_flags, ret.options);
        }
    }

    #[test]
    fn test_command_err() {
        let m =
            Cli::new("app")
                .arg(Args::new("noargs"))
                .try_get_matches_from(string_vec!["app", "--onearg", "arg"]);

        assert!(m.is_none());
    }

    #[test]
    fn test_dup_option() {
        let m =
            Cli::new("app")
                .arg(Args::new("dupargs").short('d'))
                .try_get_matches_from(string_vec!["app", "--dupargs", "-d"]);

        assert!(m.is_none());
    }

    #[test]
    fn test_args_match() {
        let m = ArgMatches {
            name: string!("git"),
            args: string_vec![],
            options: hash! {
                string!("-n") => string_vec!["namespace"],
            },
            sub_command: hash! {
                string!("add") => ArgMatches {
                    name: string!("add"),
                    args: string_vec!["resp"],
                    sub_command: hash!{},
                    options: hash!{
                        string!("-p") => string_vec!["path"],
                        string!("-h") => string_vec!["add help"],
                    }
                }
            },
        };

        if let Some(v) = m.value_of("-v") {
            assert!(false);
        }

        if let Some(m) = m.sub_command("add") {
            let ref resp = m.args()[0];
            assert_eq!("resp", resp);
            if let Some(option) = m.value_of("-p") {
                assert_eq!("path", option[0]);
            }

            if let Some(option) = m.value_of("-h") {
                assert_eq!("add help", option[0]);
            }
        }

        if let Some(n) = m.value_of("-n") {
            assert_eq!("namespace", n[0]);
        }
    }

    #[test]
    fn test_cli_args() {
        let m =
            Cli::new("app")
                .arg(Args::new("noargs"))
                .arg(Args::new("onearg").takes_value())
                .arg(Args::new("notused").takes_value())
                .try_get_matches_from(string_vec!["app", "--noargs", "--onearg", "arg"])
                .unwrap();

        let no_args = m.value_of("noargs").unwrap();
        assert_eq!(0, no_args.len());

        let one_args = m.value_of("onearg").unwrap();
        assert_eq!(1, one_args.len());
        assert_eq!(string!("arg"), one_args[0]);

        assert_eq!(None, m.value_of("notused"));
    }

    #[test]
    fn test_short() {
        let m =
            Cli::new("app")
                .arg(Args::new("noargs").short('n'))
                .arg(Args::new("onearg").short('o').takes_value())
                .try_get_matches_from(string_vec!["app", "-n", "-o", "arg"])
                .unwrap();

        let no_args = m.value_of("noargs").unwrap();
        assert_eq!(0, no_args.len());

        let one_args = m.value_of("onearg").unwrap();
        assert_eq!(1, one_args.len());
        assert_eq!(string!("arg"), one_args[0]);
    }

    #[test]
    fn test_subcommand() {
        let m =
            Cli::new("app")
                .subcommand(
                    SubCommand::new("add")
                        .arg(Args::new("noargs"))
                        .arg(Args::new("onearg").takes_value())
                )
                .subcommand(SubCommand::new("copy").takes_value())
                .try_get_matches_from(string_vec!["app", "add", "--noargs", "--onearg", "arg"])
                .unwrap();

        let sub_cmd = m.sub_command("add").unwrap();

        let no_args = sub_cmd.value_of("noargs").unwrap();
        assert_eq!(0, no_args.len());

        let one_arg = sub_cmd.value_of("onearg").unwrap();
        assert_eq!(1, one_arg.len());
        assert_eq!(string!("arg"), one_arg[0]);
    }

    #[test]
    fn test_subcommand_with_parameter() {
        let m =
            Cli::new("app")
                .subcommand(SubCommand::new("copy").takes_value())
                .try_get_matches_from(string_vec!["app", "copy", "arg"])
                .unwrap();

        let sub_cmd = m.sub_command("copy").unwrap();
        assert_eq!(1, sub_cmd.args().len());
        assert_eq!(string!("arg"), sub_cmd.args()[0]);
    }

    #[test]
    fn test_no_such_option() {
        let m =
            Cli::new("app")
                .arg(Args::new("version"))
                .try_get_matches_from(string_vec!["app", "-v"]);

        assert!(m.is_none());
    }

    #[test]
    fn test_option_invalid() {
        let m =
            Cli::new("app")
                .arg(Args::new("version").takes_value().short('v'))
                .try_get_matches_from(string_vec!["app", "-v"]);

        assert!(m.is_none());

        let m =
            Cli::new("app")
                .arg(Args::new("version").required())
                .try_get_matches_from(string_vec!["app", "--help"]);

        assert!(m.is_none());

        let m =
            Cli::new("app")
                .arg(Args::new("version").required().arg_count(3).short('v'))
                .try_get_matches_from(string_vec!["app", "-v", "arg1", "arg2"]);

        assert!(m.is_none());
    }

    #[test]
    #[should_panic]
    fn test_panic_when_build() {
        let m =
            Cli::new("app")
                .arg(Args::new("noargs").short('n'))
                .arg(Args::new("onearg").short('n'))
                .try_get_matches_from(string_vec!["app", "copy", "arg"])
                .unwrap();
    }
}
