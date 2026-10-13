//! Build gate: a protocol that arkham can serve, or that the compose demo
//! configures, has a scenario the demo client actually runs.
//!
//! Supported protocols are the [`Scheme`](arkham_config::grants::Scheme)
//! variants in `arkham-config` and the directories under
//! `crates/arkham-proxy/src/transports/` (the shared `engine` directory is
//! not a protocol). The directory name is the protocol id. A scheme maps to
//! the directory of the same name, or to the longest directory name that is
//! a prefix of the scheme (`https` → `http`, `rediss` → `redis`).
//!
//! Configured protocols are URL schemes quoted in `integration/arkham.toml`.
//! A scenario is a `retry()` label in `integration/client/run.ts` that
//! contains the scheme as a token (`https`, `redis`). The `rediss` scheme is
//! covered by a label that names `redis` and `tls`. The label has to sit on
//! a path the compose client runs: an `if (NAME)` whose `NAME` is
//! `const NAME = process.env.KEY` counts only when `KEY` is in the `client`
//! service environment, and the `else` arm does not count. A shared function
//! called as `fn("tls")` and `fn("plaintext")` attributes each label to the
//! call whose argument the label names.

use std::collections::{BTreeMap, BTreeSet};

/// One `retry()` label and the env vars that must be set for that path to run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FoundLabel {
  text: String,
  gates: Vec<String>,
}

/// Inputs the gate reads. Tests pass fixtures; the repo test reads the tree.
struct CoverageInputs<'a> {
  scheme_src: &'a str,
  transport_dirs: &'a [String],
  arkham_toml: &'a str,
  run_ts: &'a str,
  compose: &'a str,
}

impl CoverageInputs<'_> {
  /// Gaps that should fail the build. Empty means every supported and configured
  /// protocol has a live compose scenario.
  fn gaps(&self) -> Vec<String> {
    let mut gaps = Vec::new();
    let variants = match self.scheme_src.scheme_variants() {
      Ok(variants) => variants,
      Err(err) => return vec![format!("reading Scheme: {err}")],
    };
    let env = match self.compose.client_env_keys() {
      Ok(env) => env,
      Err(err) => return vec![format!("reading compose client environment: {err}")],
    };
    let found = match Parser::new(self.run_ts).found_labels() {
      Ok(found) => found,
      Err(err) => return vec![format!("reading integration/client/run.ts: {err}")],
    };
    let live: Vec<String> = found
      .into_iter()
      .filter(|label| label.gates.iter().all(|gate| env.contains(gate)))
      .map(|label| label.text)
      .collect();

    let mut protocols = BTreeSet::new();
    for variant in &variants {
      let scheme = variant.to_ascii_lowercase();
      let Some(protocol) = self.transport_dirs.protocol_id(&scheme) else {
        gaps.push(format!(
          "Scheme::{variant} ({scheme}) has no transport directory under crates/arkham-proxy/src/transports"
        ));
        continue;
      };
      protocols.insert(protocol.to_string());
      if !live.covers(&scheme, protocol) {
        gaps.push(format!(
          "Scheme::{variant} ({scheme}) has no live e2e scenario. A retry() label in integration/client/run.ts must contain `{scheme}` as a token, on a path whose if (ENV) guards are set in the compose client environment. `{protocol}` over TLS is covered by a label that contains `{protocol}` and `tls`. Live labels:\n{}",
          live.join("\n")
        ));
      }
    }
    for dir in self.transport_dirs {
      if !protocols.contains(dir) {
        gaps.push(format!(
          "transport `{dir}` is supported but no Scheme variant maps to it (directory name, or a scheme prefixed by that name)"
        ));
      }
    }
    for scheme in self.arkham_toml.configured_schemes() {
      if !variants.iter().any(|variant| variant.eq_ignore_ascii_case(&scheme)) {
        gaps.push(format!(
          "configured scheme `{scheme}` in integration/arkham.toml is not a Scheme variant"
        ));
      }
    }
    gaps
  }
}

/// Methods on the strings this gate parses: scheme source, compose, config, and labels.
trait CoverageText {
  /// `https` is its own token, so it does not satisfy `http`.
  fn contains_token(&self, needle: &str) -> bool;
  fn is_word(&self) -> bool;
  fn is_js_keyword(&self) -> bool;
  fn mentions_any(&self, tokens: &BTreeSet<String>) -> bool;
  fn scheme_variants(&self) -> Result<Vec<String>, String>;
  fn variant_name(&self) -> Option<String>;
  fn configured_schemes(&self) -> BTreeSet<String>;
  fn url_scheme(&self) -> Option<String>;
  fn client_env_keys(&self) -> Result<BTreeSet<String>, String>;
}

impl CoverageText for str {
  fn contains_token(&self, needle: &str) -> bool {
    if needle.is_empty() {
      return false;
    }
    let hay = self.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    hay.match_indices(&needle).any(|(at, _)| {
      let before = hay.get(..at).and_then(|prefix| prefix.chars().next_back());
      let after = hay.get(at + needle.len()..).and_then(|suffix| suffix.chars().next());
      before.is_none_or(|ch| !ch.is_ascii_alphanumeric()) && after.is_none_or(|ch| !ch.is_ascii_alphanumeric())
    })
  }

  fn is_word(&self) -> bool {
    !self.is_empty() && self.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
  }

  fn is_js_keyword(&self) -> bool {
    matches!(
      self,
      "if"
        | "for"
        | "while"
        | "switch"
        | "catch"
        | "function"
        | "return"
        | "await"
        | "async"
        | "const"
        | "let"
        | "var"
        | "else"
        | "new"
        | "typeof"
        | "instanceof"
        | "of"
        | "in"
        | "from"
        | "import"
        | "export"
        | "class"
        | "try"
        | "throw"
        | "break"
        | "continue"
        | "case"
        | "default"
        | "do"
        | "yield"
        | "void"
        | "delete"
        | "this"
        | "super"
    )
  }

  fn mentions_any(&self, tokens: &BTreeSet<String>) -> bool {
    tokens.iter().any(|token| self.contains_token(token))
  }

  fn scheme_variants(&self) -> Result<Vec<String>, String> {
    let start = self.find("pub enum Scheme").ok_or("missing `pub enum Scheme`")?;
    let after = self.get(start..).ok_or("scheme slice")?;
    let open = after.find('{').ok_or("scheme brace")?;
    let mut depth = 0i32;
    let mut end = None;
    for (idx, ch) in after.get(open..).unwrap_or("").char_indices() {
      match ch {
        '{' => depth += 1,
        '}' => {
          depth -= 1;
          if depth == 0 {
            end = Some(open.saturating_add(idx));
            break;
          }
        }
        _ => {}
      }
    }
    let end = end.ok_or("unclosed Scheme enum")?;
    let body = after.get(open.saturating_add(1)..end).ok_or("scheme body")?;
    let mut names = Vec::new();
    for line in body.lines() {
      if let Some(name) = line.variant_name() {
        names.push(name);
      }
    }
    if names.is_empty() {
      return Err("Scheme enum has no variants".to_string());
    }
    Ok(names)
  }

  fn variant_name(&self) -> Option<String> {
    let line = self.trim();
    if line.is_empty() || line.starts_with('/') || line.starts_with('#') || line.starts_with('[') {
      return None;
    }
    let name: String = line.chars().take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_').collect();
    if name.is_empty() || !name.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()) {
      return None;
    }
    let rest = line.get(name.len()..)?.trim_start();
    rest.starts_with([',', '{', '(']).then_some(name)
  }

  fn configured_schemes(&self) -> BTreeSet<String> {
    let mut schemes = BTreeSet::new();
    let mut rest = self;
    while let Some(start) = rest.find('"') {
      let after = rest.get(start.saturating_add(1)..).unwrap_or("");
      let Some(end) = after.find('"') else { break };
      let quoted = after.get(..end).unwrap_or("");
      if let Some(scheme) = quoted.url_scheme() {
        schemes.insert(scheme);
      }
      rest = after.get(end.saturating_add(1)..).unwrap_or("");
    }
    schemes
  }

  fn url_scheme(&self) -> Option<String> {
    let (scheme, tail) = self.split_once("://")?;
    if scheme.is_empty()
      || !scheme
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '+' | '-' | '.'))
    {
      return None;
    }
    if tail.is_empty() {
      return None;
    }
    Some(scheme.to_string())
  }

  fn client_env_keys(&self) -> Result<BTreeSet<String>, String> {
    let lines: Vec<&str> = self.lines().collect();
    let client = lines
      .iter()
      .position(|line| *line == "  client:")
      .ok_or("compose has no `client` service")?;
    let mut env_at = None;
    for (offset, line) in lines.iter().enumerate().skip(client.saturating_add(1)) {
      if line.starts_with("  ") && !line.starts_with("   ") && !line.is_empty() {
        break;
      }
      if *line == "    environment:" {
        env_at = Some(offset);
        break;
      }
    }
    let env_at = env_at.ok_or("client service has no environment")?;
    let mut keys = BTreeSet::new();
    for line in lines.iter().skip(env_at.saturating_add(1)) {
      if let Some(rest) = line.strip_prefix("      ") {
        let key = rest.split(':').next().unwrap_or("").trim();
        if !key.is_empty() && key.chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_') {
          keys.insert(key.to_string());
        }
      } else if !(line.trim().is_empty() || line.trim_start().starts_with('#')) {
        break;
      }
    }
    if keys.is_empty() {
      return Err("client environment has no keys".to_string());
    }
    Ok(keys)
  }
}

/// Transport directories and live scenario labels are both lists of strings.
trait CoverageList {
  fn protocol_id(&self, scheme: &str) -> Option<&str>;
  /// `https` is its own token, so it does not satisfy `http`. `rediss` has no
  /// token in the Redis labels; a `redis` + `tls` label is that scheme's scenario.
  fn covers(&self, scheme: &str, protocol: &str) -> bool;
}

impl CoverageList for [String] {
  fn protocol_id(&self, scheme: &str) -> Option<&str> {
    if let Some(exact) = self.iter().find(|dir| dir.as_str() == scheme) {
      return Some(exact.as_str());
    }
    self
      .iter()
      .filter(|dir| !dir.is_empty() && scheme.starts_with(dir.as_str()))
      .max_by_key(|dir| dir.len())
      .map(String::as_str)
  }

  fn covers(&self, scheme: &str, protocol: &str) -> bool {
    if self.iter().any(|label| label.contains_token(scheme)) {
      return true;
    }
    scheme != protocol
      && self
        .iter()
        .any(|label| label.contains_token(protocol) && label.contains_token("tls"))
  }
}

/// ASCII identifier characters in the client script.
trait JsIdent {
  fn starts_js_ident(self) -> bool;
  fn continues_js_ident(self) -> bool;
}

impl JsIdent for char {
  fn starts_js_ident(self) -> bool {
    self.is_ascii_alphabetic() || self == '_' || self == '$'
  }

  fn continues_js_ident(self) -> bool {
    self.is_ascii_alphanumeric() || self == '_' || self == '$'
  }
}

#[derive(Debug, Clone)]
struct LocalLabel {
  func: String,
  text: String,
  gates: Vec<String>,
}

#[derive(Debug, Clone)]
struct Call {
  caller: String,
  callee: String,
  gates: Vec<String>,
  arg_strings: Vec<String>,
}

#[derive(Debug)]
struct Parser<'a> {
  src: &'a str,
  i: usize,
  depth: i32,
  paren: i32,
  frames: Vec<Frame>,
  gates: Vec<Gate>,
  just_closed: Option<Gate>,
  pending: Option<ArgKind>,
  arg: Option<ArgCollect>,
  binding: Option<Binding>,
  env_of: BTreeMap<String, String>,
  bindings: BTreeMap<String, Vec<String>>,
  labels: Vec<LocalLabel>,
  calls: Vec<Call>,
}

#[derive(Debug)]
struct Frame {
  name: String,
  body_depth: Option<i32>,
}

#[derive(Debug, Clone)]
struct Gate {
  body_depth: i32,
  env: Option<String>,
  skipped: bool,
}

#[derive(Debug)]
enum ArgKind {
  Retry,
  Call(String),
}

#[derive(Debug)]
struct ArgCollect {
  kind: ArgKind,
  paren: i32,
  strings: Vec<String>,
  ident: Option<String>,
  only_ident: bool,
  caller: String,
  gates: Vec<String>,
}

#[derive(Debug)]
struct Binding {
  name: String,
  start_depth: i32,
  start_paren: i32,
  strings: Vec<String>,
  env_key: Option<String>,
  env_chain: u8,
  started: bool,
}

#[derive(Debug)]
enum Token {
  Str(String),
  Ident(String),
  LBrace,
  RBrace,
  LParen,
  RParen,
  Semi,
  Comma,
  Dot,
  Eq,
  Other,
}

enum Peek {
  LParen,
  Ident(String),
}

impl<'a> Parser<'a> {
  fn new(src: &'a str) -> Self {
    Self {
      src,
      i: 0,
      depth: 0,
      paren: 0,
      frames: vec![Frame {
        name: String::new(),
        body_depth: None,
      }],
      gates: Vec::new(),
      just_closed: None,
      pending: None,
      arg: None,
      binding: None,
      env_of: BTreeMap::new(),
      bindings: BTreeMap::new(),
      labels: Vec::new(),
      calls: Vec::new(),
    }
  }

  fn found_labels(mut self) -> Result<Vec<FoundLabel>, String> {
    self.parse()?;
    Ok(self.expand())
  }

  fn expand(&self) -> Vec<FoundLabel> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    self.walk("", &[], &[], &mut out, &mut seen);
    out
  }

  fn walk(&self, func: &str, inherited: &[String], from_args: &[String], out: &mut Vec<FoundLabel>, seen: &mut BTreeSet<String>) {
    let mark = format!("{func}|{}|{}", inherited.join(","), from_args.join(","));
    if !seen.insert(mark) {
      return;
    }
    let discriminators = self.discriminators(func);
    for label in self.labels.iter().filter(|label| label.func == func) {
      if label.text.mentions_any(&discriminators) && !from_args.iter().any(|arg| label.text.contains_token(arg)) {
        continue;
      }
      let mut gates = inherited.to_vec();
      gates.extend(label.gates.iter().cloned());
      gates.sort();
      gates.dedup();
      out.push(FoundLabel {
        text: label.text.clone(),
        gates,
      });
    }
    for call in self.calls.iter().filter(|call| call.caller == func) {
      let mut gates = inherited.to_vec();
      gates.extend(call.gates.iter().cloned());
      gates.sort();
      gates.dedup();
      let args: Vec<String> = call.arg_strings.iter().filter(|arg| arg.is_word()).cloned().collect();
      self.walk(&call.callee, &gates, &args, out, seen);
    }
  }

  fn discriminators(&self, func: &str) -> BTreeSet<String> {
    self
      .calls
      .iter()
      .filter(|call| call.callee == func)
      .flat_map(|call| call.arg_strings.iter().filter(|arg| arg.is_word()).cloned())
      .collect()
  }

  fn parse(&mut self) -> Result<(), String> {
    while let Some(tok) = self.next_token()? {
      if let Some(closed) = self.just_closed.take()
        && matches!(&tok, Token::Ident(id) if id == "else")
      {
        self.handle_else(&closed)?;
        continue;
      }
      if !matches!(tok, Token::LParen) {
        self.pending = None;
      }
      self.on_token(tok)?;
    }
    if self.depth != 0 || self.paren != 0 {
      return Err(format!("scan ended at brace depth {} paren depth {}", self.depth, self.paren));
    }
    Ok(())
  }

  fn on_token(&mut self, tok: Token) -> Result<(), String> {
    match tok {
      Token::LParen => self.on_lparen(),
      Token::RParen => self.on_rparen(),
      Token::LBrace => {}
      Token::RBrace => self.on_rbrace(),
      Token::Semi => self.on_semi(),
      Token::Comma => self.on_comma(),
      Token::Eq => self.on_eq(),
      Token::Str(text) => self.on_str(text),
      Token::Ident(id) => self.on_ident(id)?,
      Token::Dot => {
        self.note_env_chain(&Token::Dot);
        self.spoil_arg_ident();
      }
      Token::Other => self.spoil_arg_ident(),
    }
    Ok(())
  }

  fn on_lparen(&mut self) {
    let Some(kind) = self.pending.take() else { return };
    let (gates, skipped) = self.local_context();
    if skipped {
      return;
    }
    self.arg = Some(ArgCollect {
      kind,
      paren: self.paren,
      strings: Vec::new(),
      ident: None,
      only_ident: true,
      caller: self.current_func(),
      gates,
    });
  }

  fn on_rparen(&mut self) {
    let done = self.arg.as_ref().is_some_and(|arg| self.paren == arg.paren - 1);
    if done {
      self.finish_arg();
    }
  }

  fn on_comma(&mut self) {
    let done = self.arg.as_ref().is_some_and(|arg| self.paren == arg.paren);
    if done {
      self.finish_arg();
    }
  }

  fn on_semi(&mut self) {
    let done = self
      .binding
      .as_ref()
      .is_some_and(|binding| binding.started && self.depth == binding.start_depth && self.paren == binding.start_paren);
    if done {
      self.finish_binding();
    }
  }

  fn on_eq(&mut self) {
    if let Some(binding) = &mut self.binding
      && !binding.started
      && self.depth == binding.start_depth
      && self.paren == binding.start_paren
    {
      binding.started = true;
    }
    self.spoil_arg_ident();
  }

  fn on_str(&mut self, text: String) {
    if let Some(arg) = &mut self.arg
      && self.paren >= arg.paren
    {
      arg.strings.push(text.clone());
      arg.only_ident = false;
    }
    if let Some(binding) = &mut self.binding
      && binding.started
    {
      binding.strings.push(text.clone());
    }
    self.note_env_chain(&Token::Str(text));
    self.spoil_arg_ident();
  }

  fn on_ident(&mut self, id: String) -> Result<(), String> {
    if id == "if" {
      self.begin_if()?;
      return Ok(());
    }
    if id == "function" {
      self.begin_function()?;
      return Ok(());
    }
    if id == "async" && matches!(self.peek_kind()?, Some(Peek::Ident(next)) if next == "function") {
      let _ = self.next_token()?;
      self.begin_function()?;
      return Ok(());
    }
    if id == "const" || id == "let" || id == "var" {
      self.begin_binding()?;
      return Ok(());
    }
    if !id.is_js_keyword() && matches!(self.peek_kind()?, Some(Peek::LParen)) {
      self.pending = Some(if id == "retry" { ArgKind::Retry } else { ArgKind::Call(id.clone()) });
      self.note_env_chain(&Token::Ident(id));
      return Ok(());
    }
    self.note_arg_ident(&id);
    self.note_env_chain(&Token::Ident(id));
    Ok(())
  }

  fn on_rbrace(&mut self) {
    let mut innermost = None;
    while self.gates.last().is_some_and(|gate| gate.body_depth > self.depth) {
      let Some(gate) = self.gates.pop() else { break };
      if innermost.is_none() {
        innermost = Some(gate);
      }
    }
    while self
      .frames
      .last()
      .is_some_and(|frame| frame.body_depth.is_some_and(|depth| depth > self.depth))
    {
      self.frames.pop();
    }
    self.just_closed = innermost;
  }

  fn handle_else(&mut self, closed: &Gate) -> Result<(), String> {
    match self.next_token()? {
      Some(Token::Ident(id)) if id == "if" => self.begin_if(),
      Some(Token::LBrace) => {
        if closed.env.is_some() && !closed.skipped {
          self.gates.push(Gate {
            body_depth: self.depth,
            env: None,
            skipped: true,
          });
        }
        Ok(())
      }
      _ => Ok(()),
    }
  }

  fn begin_if(&mut self) -> Result<(), String> {
    let Some(name) = self.try_simple_if()? else {
      return Ok(());
    };
    let env = self.env_of.get(&name).cloned();
    self.gates.push(Gate {
      body_depth: self.depth,
      env,
      skipped: false,
    });
    Ok(())
  }

  fn try_simple_if(&mut self) -> Result<Option<String>, String> {
    let save_i = self.i;
    let save_depth = self.depth;
    let save_paren = self.paren;
    let parsed = (|| -> Result<Option<String>, String> {
      if !matches!(self.next_token()?, Some(Token::LParen)) {
        return Ok(None);
      }
      let Some(Token::Ident(name)) = self.next_token()? else {
        return Ok(None);
      };
      if !matches!(self.next_token()?, Some(Token::RParen)) {
        return Ok(None);
      }
      if !matches!(self.next_token()?, Some(Token::LBrace)) {
        return Ok(None);
      }
      Ok(Some(name))
    })()?;
    if parsed.is_none() {
      self.i = save_i;
      self.depth = save_depth;
      self.paren = save_paren;
    }
    Ok(parsed)
  }

  fn begin_function(&mut self) -> Result<(), String> {
    let paren0 = self.paren;
    let mut name = None;
    match self.next_token()? {
      Some(Token::Ident(id)) => name = Some(id),
      Some(Token::LParen) => {}
      _ => return Ok(()),
    }
    loop {
      match self.next_token()? {
        Some(Token::LBrace) if self.paren == paren0 => {
          if let Some(name) = name {
            self.frames.push(Frame {
              name,
              body_depth: Some(self.depth),
            });
          }
          return Ok(());
        }
        Some(_) => {}
        None => return Ok(()),
      }
    }
  }

  fn begin_binding(&mut self) -> Result<(), String> {
    let Some(Token::Ident(name)) = self.next_token()? else {
      return Ok(());
    };
    self.binding = Some(Binding {
      name,
      start_depth: self.depth,
      start_paren: self.paren,
      strings: Vec::new(),
      env_key: None,
      env_chain: 0,
      started: false,
    });
    Ok(())
  }

  fn finish_binding(&mut self) {
    let Some(binding) = self.binding.take() else { return };
    if let Some(key) = binding.env_key {
      self.env_of.insert(binding.name.clone(), key);
    }
    self.bindings.insert(binding.name, binding.strings);
  }

  fn finish_arg(&mut self) {
    let Some(arg) = self.arg.take() else { return };
    let texts = if !arg.strings.is_empty() {
      arg.strings
    } else if let Some(id) = arg.ident {
      self.bindings.get(&id).cloned().unwrap_or_default()
    } else {
      Vec::new()
    };
    let texts: Vec<String> = texts.into_iter().filter(|text| !text.is_empty()).collect();
    match arg.kind {
      ArgKind::Retry => {
        for text in texts {
          self.labels.push(LocalLabel {
            func: arg.caller.clone(),
            text,
            gates: arg.gates.clone(),
          });
        }
      }
      ArgKind::Call(name) => self.calls.push(Call {
        caller: arg.caller,
        callee: name,
        gates: arg.gates,
        arg_strings: texts,
      }),
    }
  }

  fn note_arg_ident(&mut self, id: &str) {
    let Some(arg) = &mut self.arg else { return };
    if self.paren == arg.paren && arg.only_ident && arg.strings.is_empty() && arg.ident.is_none() {
      arg.ident = Some(id.to_string());
    } else if self.paren >= arg.paren {
      arg.only_ident = false;
    }
  }

  fn spoil_arg_ident(&mut self) {
    if let Some(arg) = &mut self.arg
      && self.paren >= arg.paren
    {
      arg.only_ident = false;
    }
  }

  fn note_env_chain(&mut self, tok: &Token) {
    let Some(binding) = &mut self.binding else { return };
    if !binding.started {
      return;
    }
    let next = match (binding.env_chain, tok) {
      (0, Token::Ident(id)) if id == "process" => 1,
      (1, Token::Dot) => 2,
      (2, Token::Ident(id)) if id == "env" => 3,
      (3, Token::Dot) => 4,
      (4, Token::Ident(id)) => {
        binding.env_key = Some(id.clone());
        0
      }
      _ => 0,
    };
    binding.env_chain = next;
  }

  fn local_context(&self) -> (Vec<String>, bool) {
    let floor = self.frames.last().and_then(|frame| frame.body_depth).unwrap_or(0);
    let mut gates = Vec::new();
    let mut skipped = false;
    for gate in &self.gates {
      if gate.body_depth >= floor {
        if gate.skipped {
          skipped = true;
        }
        if let Some(env) = &gate.env {
          gates.push(env.clone());
        }
      }
    }
    gates.sort();
    gates.dedup();
    (gates, skipped)
  }

  fn current_func(&self) -> String {
    self.frames.last().map(|frame| frame.name.clone()).unwrap_or_default()
  }

  fn peek_kind(&mut self) -> Result<Option<Peek>, String> {
    let save_i = self.i;
    let save_depth = self.depth;
    let save_paren = self.paren;
    let tok = self.next_token()?;
    self.i = save_i;
    self.depth = save_depth;
    self.paren = save_paren;
    Ok(match tok {
      Some(Token::LParen) => Some(Peek::LParen),
      Some(Token::Ident(id)) => Some(Peek::Ident(id)),
      _ => None,
    })
  }

  fn next_token(&mut self) -> Result<Option<Token>, String> {
    self.skip_ignorable();
    let Some(ch) = self.peek_char() else { return Ok(None) };
    let tok = match ch {
      '"' | '\'' => {
        self.bump();
        Token::Str(self.read_quoted(ch)?)
      }
      '`' => {
        self.bump();
        Token::Str(self.read_template()?)
      }
      '{' => {
        self.bump();
        self.depth += 1;
        Token::LBrace
      }
      '}' => {
        self.bump();
        self.depth -= 1;
        Token::RBrace
      }
      '(' => {
        self.bump();
        self.paren += 1;
        Token::LParen
      }
      ')' => {
        self.bump();
        self.paren -= 1;
        Token::RParen
      }
      ';' => {
        self.bump();
        Token::Semi
      }
      ',' => {
        self.bump();
        Token::Comma
      }
      '.' => {
        self.bump();
        Token::Dot
      }
      '=' => {
        self.bump();
        if self.peek_char() == Some('=') || self.peek_char() == Some('>') {
          self.bump();
          Token::Other
        } else {
          Token::Eq
        }
      }
      ch if ch.starts_js_ident() => Token::Ident(self.read_ident()),
      _ => {
        self.bump();
        Token::Other
      }
    };
    Ok(Some(tok))
  }

  fn read_quoted(&mut self, quote: char) -> Result<String, String> {
    let mut text = String::new();
    loop {
      let ch = self.bump().ok_or_else(|| "unterminated string".to_string())?;
      if ch == quote {
        return Ok(text);
      }
      if ch == '\\' {
        if let Some(escaped) = self.bump() {
          text.push(escaped);
        }
        continue;
      }
      text.push(ch);
    }
  }

  fn read_template(&mut self) -> Result<String, String> {
    let mut text = String::new();
    loop {
      let ch = self.bump().ok_or_else(|| "unterminated template".to_string())?;
      if ch == '`' {
        return Ok(text);
      }
      if ch == '$' && self.peek_char() == Some('{') {
        self.bump();
        self.depth += 1;
        let target = self.depth;
        text.push(' ');
        loop {
          let Some(_) = self.next_token()? else {
            return Err("unterminated template expression".to_string());
          };
          if self.depth < target {
            break;
          }
        }
        continue;
      }
      if ch == '\\' {
        if let Some(escaped) = self.bump() {
          text.push(escaped);
        }
        continue;
      }
      text.push(ch);
    }
  }

  fn skip_ignorable(&mut self) {
    loop {
      if self.starts_with("//") {
        while let Some(ch) = self.bump() {
          if ch == '\n' {
            break;
          }
        }
        continue;
      }
      if self.starts_with("/*") {
        let _ = self.bump_str("/*");
        while !self.starts_with("*/") && self.bump().is_some() {}
        let _ = self.bump_str("*/");
        continue;
      }
      if self.peek_char().is_some_and(char::is_whitespace) {
        self.bump();
        continue;
      }
      break;
    }
  }

  fn read_ident(&mut self) -> String {
    let start = self.i;
    if self.peek_char().is_some_and(JsIdent::starts_js_ident) {
      self.bump();
    }
    while self.peek_char().is_some_and(JsIdent::continues_js_ident) {
      self.bump();
    }
    self.src.get(start..self.i).unwrap_or("").to_string()
  }

  fn peek_char(&self) -> Option<char> {
    self.src.get(self.i..)?.chars().next()
  }

  fn bump(&mut self) -> Option<char> {
    let ch = self.peek_char()?;
    self.i = self.i.saturating_add(ch.len_utf8());
    Some(ch)
  }

  fn starts_with(&self, prefix: &str) -> bool {
    self.src.get(self.i..).is_some_and(|rest| rest.starts_with(prefix))
  }

  fn bump_str(&mut self, prefix: &str) -> bool {
    if self.starts_with(prefix) {
      self.i = self.i.saturating_add(prefix.len());
      true
    } else {
      false
    }
  }
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::path::{Path, PathBuf};

  use super::*;

  fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
  }

  fn read_repo(path: &str) -> String {
    let full = repo_root().join(path);
    fs::read_to_string(&full).unwrap_or_else(|err| panic!("read {}: {err}", full.display()))
  }

  fn transport_dirs(root: &Path) -> Vec<String> {
    let dir = root.join("crates/arkham-proxy/src/transports");
    let mut names = Vec::new();
    let entries = fs::read_dir(&dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display()));
    for entry in entries {
      let entry = entry.unwrap_or_else(|err| panic!("transport dir entry: {err}"));
      if !entry.path().is_dir() {
        continue;
      }
      let name = entry.file_name().to_string_lossy().into_owned();
      if name != "engine" {
        names.push(name);
      }
    }
    names.sort();
    names
  }

  fn live(src: &str, compose: &str) -> Vec<FoundLabel> {
    let env = compose.client_env_keys().expect("client env");
    Parser::new(src)
      .found_labels()
      .expect("scan")
      .into_iter()
      .filter(|label| label.gates.iter().all(|gate| env.contains(gate)))
      .collect()
  }

  #[test]
  fn scheme_parser_reads_variants_and_skips_docs() {
    let src = "pub enum Scheme {\n  /// Plain HTTP.\n  Http,\n  Https,\n}\n";
    assert_eq!(src.scheme_variants().expect("variants"), ["Http", "Https"]);
  }

  #[test]
  fn else_arm_is_not_a_live_scenario() {
    let src = r#"
      const PG_URL = process.env.DATABASE_URL ?? "";
      if (PG_URL) {
        await retry("kept", async () => {});
      } else {
        await retry("postgres mitm skipped", async () => {});
      }
    "#;
    let compose = "services:\n  client:\n    environment:\n      DATABASE_URL: x\n    volumes: []\n";
    let labels = live(src, compose);
    assert!(labels.iter().any(|label| label.text == "kept"));
    assert!(!labels.iter().any(|label| label.text.contains("postgres")));
  }

  #[test]
  fn regex_braces_do_not_drop_the_following_scenario() {
    let src = r#"
      const PG_URL = process.env.DATABASE_URL ?? "";
      if (PG_URL) {
        if (!/^[0-9a-f]{32}$/.test(x)) return false;
        await retry("postgres mitm ok", async () => {});
      }
    "#;
    let compose = "services:\n  client:\n    environment:\n      DATABASE_URL: x\n    volumes: []\n";
    let labels = live(src, compose);
    assert!(labels.iter().any(|label| label.text == "postgres mitm ok"));
  }

  #[test]
  fn shared_function_attributes_tls_labels_to_the_tls_call() {
    let src = r#"
      const REDIS_URL = process.env.REDIS_URL ?? "";
      const REDIS_TLS_URL = process.env.REDIS_TLS_URL ?? "";
      async function redisScenarios(kind) {
        const requirepass = kind === "plaintext" ? "redis plaintext requirepass" : "redis tls requirepass";
        await retry(requirepass, async () => {});
        await retry(`redis ${kind} ACL`, async () => {});
      }
      if (REDIS_URL) {
        await redisScenarios("plaintext", REDIS_URL);
      }
      if (REDIS_TLS_URL) {
        await redisScenarios("tls", REDIS_TLS_URL);
      }
    "#;
    let both = "services:\n  client:\n    environment:\n      REDIS_URL: a\n      REDIS_TLS_URL: b\n    volumes: []\n";
    let labels = live(src, both);
    assert!(
      labels
        .iter()
        .any(|label| label.text.contains("redis plaintext") && label.gates == ["REDIS_URL"])
    );
    assert!(
      labels
        .iter()
        .any(|label| label.text.contains("redis tls") && label.gates == ["REDIS_TLS_URL"])
    );
    let plain = "services:\n  client:\n    environment:\n      REDIS_URL: a\n    volumes: []\n";
    let labels = live(src, plain);
    assert!(labels.iter().any(|label| label.text.contains("redis plaintext")));
    assert!(!labels.iter().any(|label| label.text.contains("redis tls requirepass")));
  }

  #[test]
  fn missing_scenario_and_unknown_scheme_are_gaps() {
    let scheme_src = "pub enum Scheme {\n  Redis,\n  Rediss,\n}\n";
    let dirs = vec!["redis".to_string()];
    let run_ts = r#"
      const REDIS_URL = process.env.REDIS_URL ?? "";
      if (REDIS_URL) {
        await retry("redis plaintext requirepass", async () => {});
      }
    "#;
    let compose = "services:\n  client:\n    environment:\n      REDIS_URL: a\n    volumes: []\n";
    let toml = "value = \"redis://cache/0\"\nvalue = \"mysql://db\"\n";
    let gaps = CoverageInputs {
      scheme_src,
      transport_dirs: &dirs,
      arkham_toml: toml,
      run_ts,
      compose,
    }
    .gaps();
    let text = gaps.join("\n");
    assert!(text.contains("Rediss"), "{text}");
    assert!(text.contains("mysql"), "{text}");
    assert!(!text.contains("Scheme::Redis (redis) has no live"), "{text}");
  }

  #[test]
  fn supported_and_configured_protocols_have_live_e2e_scenarios() {
    let root = repo_root();
    let scheme_src = read_repo("crates/arkham-config/src/grants/mod.rs");
    let variants = scheme_src.scheme_variants().expect("Scheme variants");
    for required in ["Http", "Https", "Tcp", "Postgres", "Redis", "Rediss", "Ssh"] {
      assert!(
        variants.iter().any(|variant| variant == required),
        "parser missed {required}: {variants:?}"
      );
    }
    let dirs = transport_dirs(&root);
    let arkham_toml = read_repo("integration/arkham.toml");
    let run_ts = read_repo("integration/client/run.ts");
    let compose = read_repo("integration/compose.yaml");
    let gaps = CoverageInputs {
      scheme_src: &scheme_src,
      transport_dirs: &dirs,
      arkham_toml: &arkham_toml,
      run_ts: &run_ts,
      compose: &compose,
    }
    .gaps();
    assert!(gaps.is_empty(), "protocol e2e coverage gaps:\n{}", gaps.join("\n"));
  }
}
