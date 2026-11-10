//! Where each string that FLOSS found goes in the database, as a synthetic string.
//!
//! A synthetic string has an address, where the Strings window jumps to, and two lists of
//! related instructions: the parts that build it, and the uses that consume it. IDA shows
//! the string as a comment at each use, or at the address when there are no uses.
//! Among the strings of one provider at one address, the listing shows only the first.
//!
//! So each string gets an address that says where it comes to exist:
//!   - a string in global memory: its own address, when that memory only ever holds this
//!     one string. Its uses are the instructions that refer to the address, other than
//!     those that wrote it. Without any, it's repeatable.
//!   - a string that a call to a decoding routine returns: the call, which is also a use,
//!     so the string shows there.
//!   - a string that a function builds itself, on the stack or elsewhere: the first of
//!     its instructions that wrote it.
//!
//! The uses are also the instructions that read the string and the calls that took a
//! pointer to it, as far as the emulator saw them.
//!
//! When another string already has that address, the string takes the next instruction
//! that wrote it, so that both show in the listing. A function has each string once: when
//! it makes the same string again, that adds to the uses and parts of the first.
//!
//! A routine that builds a string and consumes it leaves the string in memory, where the
//! call to the routine finds it again. That one isn't a string of its own: its uses and
//! parts go to the string inside the routine.
//!
//! A decoded string whose text the program also has as a static string isn't a synthetic
//! string. Mostly the routine copied it from there, and the Strings window has the
//! original. Stack strings and tight strings stay, since their function builds them.
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use floss::results::{AddressType, DecodedString, Strings};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticString {
    pub text:       String,
    /// show the string at the instructions that refer to its address.
    pub repeatable: bool,
    pub uses:       Vec<u64>,
    pub parts:      Vec<u64>,
}

/// What the plugin needs to know about the database.
pub trait Database {
    /// the start of the function that contains the address.
    fn get_function_start(&self, ea: u64) -> Option<u64>;
    fn is_mapped(&self, ea: u64) -> bool;
    /// the instructions that refer to the data at the address.
    fn get_instructions_referring_to(&self, ea: u64) -> Vec<u64>;
    /// whether the bytes of the program have this text as a string.
    fn has_static_string(&self, text: &str) -> bool;
}

/// The synthetic strings for the strings that FLOSS found, by address.
pub fn get_synthetic_strings(strings: &Strings, db: &impl Database) -> BTreeMap<u64, Vec<SyntheticString>> {
    let get_function = |s: &DecodedString| db.get_function_start(s.decoded_at).unwrap_or(s.decoding_routine);
    // the instructions of the function among those that wrote one of its strings: the others are in its callees.
    let get_own = |function: u64, writers: &[u64]| -> Vec<u64> {
        writers.iter().copied().filter(|ea| db.get_function_start(*ea) == Some(function)).collect()
    };

    // the texts that each global address held, and the texts that came to exist in each function.
    let mut texts: HashMap<u64, HashSet<&str>> = HashMap::new();
    let mut in_function: HashSet<(u64, &str)> = HashSet::new();
    for s in strings.stack_strings.iter().chain(&strings.tight_strings) {
        in_function.insert((s.function, &s.string));
    }
    for s in &strings.decoded_strings {
        in_function.insert((get_function(s), &s.string));
        if matches!(s.address_type, AddressType::Global) {
            texts.entry(s.address).or_default().insert(&s.string);
        }
    }

    let mut placed = Placed::default();
    let mut leftovers = vec![];
    for s in strings.stack_strings.iter().chain(&strings.tight_strings) {
        let anchors = get_own(s.function, &s.writers).into_iter().chain([s.program_counter, s.function]);
        placed.place(s.function, anchors, &s.string, false, get_uses(&s.readers, &s.passed_to), &s.writers);
    }
    for s in &strings.decoded_strings {
        if db.has_static_string(&s.string) {
            continue;
        }
        let uses = get_uses(&s.readers, &s.passed_to);
        let is_global = matches!(s.address_type, AddressType::Global) && db.is_mapped(s.address);
        if is_global && texts[&s.address].len() == 1 {
            let mut refs = db.get_instructions_referring_to(s.address);
            refs.retain(|ea| !s.writers.contains(ea));
            let uses = get_uses(&uses, &refs);
            placed.place(get_function(s), [s.address], &s.string, uses.is_empty(), uses, &s.writers);
        } else if !is_returned(s, db) {
            let anchors = get_own(s.decoding_routine, &s.writers).into_iter().chain([s.decoded_at, s.decoding_routine]);
            placed.place(s.decoding_routine, anchors, &s.string, false, uses, &s.writers);
        } else if !uses.is_empty() && in_function.contains(&(s.decoding_routine, s.string.as_str())) {
            leftovers.push(s);
        } else {
            placed.place(get_function(s), [s.decoded_at], &s.string, false, vec![s.decoded_at], &s.writers);
        }
    }
    for s in leftovers {
        let uses = get_uses(&s.readers, &s.passed_to);
        if placed.made.contains_key(&(s.decoding_routine, s.string.clone())) {
            placed.place(s.decoding_routine, [], &s.string, false, uses, &s.writers);
        } else if !placed.strings.values().flatten().any(|other| other.text == s.string) {
            placed.place(get_function(s), [s.decoded_at], &s.string, false, get_uses(&uses, &[s.decoded_at]), &s.writers);
        }
    }
    placed.strings
}

/// whether a call to a decoding routine decoded the string, rather than the function that it's reported for.
fn is_returned(s: &DecodedString, db: &impl Database) -> bool {
    db.get_function_start(s.decoded_at).is_some_and(|f| f != s.decoding_routine)
}

fn get_uses(readers: &[u64], passed_to: &[u64]) -> Vec<u64> {
    let uses: BTreeSet<u64> = readers.iter().chain(passed_to).copied().collect();
    uses.into_iter().collect()
}

#[derive(Default)]
struct Placed {
    strings: BTreeMap<u64, Vec<SyntheticString>>,
    /// where each string of a function is, by function and text.
    made:    HashMap<(u64, String), u64>,
}

impl Placed {
    /// Put the string at the first of the anchors that no other string has. A function has
    /// each string once: when it already has this one, add to the uses and parts of that.
    fn place(
        &mut self,
        function: u64,
        anchors: impl IntoIterator<Item = u64>,
        text: &str,
        repeatable: bool,
        uses: Vec<u64>,
        parts: &[u64],
    ) {
        let anchors: Vec<u64> = anchors.into_iter().collect();
        let is_free = |ea: &u64| self.strings.get(ea).is_none_or(|at| at.iter().any(|s| s.text == text));
        let key = (function, text.to_string());
        let Some(&ea) = self.made.get(&key).or(anchors.iter().find(|ea| is_free(ea))).or(anchors.first()) else {
            return;
        };
        self.made.insert(key, ea);

        let at = self.strings.entry(ea).or_default();
        match at.iter_mut().find(|s| s.text == text) {
            Some(s) => {
                s.repeatable &= repeatable;
                s.uses = get_uses(&s.uses, &uses);
                s.parts = get_uses(&s.parts, parts);
            }
            None => at.push(SyntheticString {
                text: text.to_string(),
                repeatable,
                uses,
                parts: get_uses(parts, &[]),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use floss::{results::StackString, strings::Encoding};

    /// functions, as (start, end), the mapped range, references, as (from, to), and static strings.
    struct Db(Vec<(u64, u64)>, (u64, u64), Vec<(u64, u64)>, Vec<&'static str>);

    impl Database for Db {
        fn get_function_start(&self, ea: u64) -> Option<u64> {
            self.0.iter().find(|(start, end)| (*start..*end).contains(&ea)).map(|f| f.0)
        }

        fn is_mapped(&self, ea: u64) -> bool {
            (self.1 .0..self.1 .1).contains(&ea)
        }

        fn get_instructions_referring_to(&self, ea: u64) -> Vec<u64> {
            self.2.iter().filter(|(_, to)| *to == ea).map(|(from, _)| *from).collect()
        }

        fn has_static_string(&self, text: &str) -> bool {
            self.3.contains(&text)
        }
    }

    fn db() -> Db {
        Db(vec![(0x1000, 0x1100), (0x1100, 0x1200), (0x1200, 0x1300)], (0x1000, 0x4000), vec![], vec![])
    }

    fn stack(string: &str, writers: &[u64], passed_to: &[u64]) -> StackString {
        StackString {
            function:               0x1000,
            string:                 string.to_string(),
            encoding:               Encoding::Ascii,
            program_counter:        0x1080,
            stack_pointer:          0,
            original_stack_pointer: 0,
            offset:                 0,
            frame_offset:           0,
            writers:                writers.to_vec(),
            readers:                vec![],
            passed_to:              passed_to.to_vec(),
        }
    }

    fn decoded(string: &str, address: u64, address_type: AddressType, decoded_at: u64, routine: u64) -> DecodedString {
        DecodedString {
            address,
            address_type,
            string: string.to_string(),
            encoding: Encoding::Ascii,
            decoded_at,
            decoding_routine: routine,
            writers: vec![0x1110, 0x1120],
            readers: vec![0x1130],
            passed_to: vec![0x1140],
        }
    }

    fn texts(strings: &BTreeMap<u64, Vec<SyntheticString>>) -> Vec<(u64, &str)> {
        strings.iter().flat_map(|(ea, at)| at.iter().map(|s| (*ea, s.text.as_str()))).collect()
    }

    #[test]
    fn stack_string_is_at_its_first_writer_with_its_uses() {
        let strings = Strings {
            stack_strings: vec![stack("kernel32.dll", &[0x1004, 0x100b], &[0x1064])],
            ..Default::default()
        };
        let synth = get_synthetic_strings(&strings, &db());
        assert_eq!(
            synth[&0x1004],
            vec![SyntheticString {
                text:       "kernel32.dll".to_string(),
                repeatable: false,
                uses:       vec![0x1064],
                parts:      vec![0x1004, 0x100b],
            }]
        );
    }

    #[test]
    fn strings_that_share_writers_get_addresses_of_their_own() {
        let strings = Strings {
            stack_strings: vec![
                stack("goodbye ", &[0x1004, 0x1008], &[]),
                stack("goodbye moon", &[0x1004, 0x1008, 0x1010], &[]),
                stack("goodbye ", &[0x1004], &[0x1050]),
            ],
            ..Default::default()
        };
        let synth = get_synthetic_strings(&strings, &db());
        assert_eq!(texts(&synth), vec![(0x1004, "goodbye "), (0x1008, "goodbye moon")]);
        assert_eq!(synth[&0x1004][0].uses, vec![0x1050]);
    }

    #[test]
    fn stack_string_is_at_an_instruction_of_its_function() {
        let strings = Strings {
            stack_strings: vec![stack("kernel32.dll", &[0x1110, 0x1008], &[])],
            ..Default::default()
        };
        assert_eq!(texts(&get_synthetic_strings(&strings, &db())), vec![(0x1008, "kernel32.dll")]);
    }

    #[test]
    fn stack_string_without_writers_is_where_it_was_found() {
        let strings = Strings {
            stack_strings: vec![stack("kernel32.dll", &[], &[])],
            ..Default::default()
        };
        assert_eq!(texts(&get_synthetic_strings(&strings, &db())), vec![(0x1080, "kernel32.dll")]);
    }

    #[test]
    fn global_string_shows_at_the_instructions_that_refer_to_it() {
        let strings = Strings {
            decoded_strings: vec![decoded("C:\\malware.exe", 0x3000, AddressType::Global, 0x1050, 0x1100)],
            ..Default::default()
        };
        let db = Db(db().0, db().1, vec![(0x1110, 0x3000), (0x1060, 0x3000), (0x1070, 0x3008)], vec![]);
        let synth = get_synthetic_strings(&strings, &db);
        assert_eq!(
            synth[&0x3000],
            vec![SyntheticString {
                text:       "C:\\malware.exe".to_string(),
                repeatable: false,
                uses:       vec![0x1060, 0x1130, 0x1140],
                parts:      vec![0x1110, 0x1120],
            }]
        );
    }

    #[test]
    fn global_string_without_uses_is_repeatable() {
        let mut string = decoded("C:\\malware.exe", 0x3000, AddressType::Global, 0x1050, 0x1100);
        (string.readers, string.passed_to) = (vec![], vec![]);
        let strings = Strings { decoded_strings: vec![string], ..Default::default() };
        let synth = get_synthetic_strings(&strings, &db());
        assert!(synth[&0x3000][0].repeatable);
        assert!(synth[&0x3000][0].uses.is_empty());
    }

    #[test]
    fn returned_string_is_at_the_call() {
        let strings = Strings {
            decoded_strings: vec![
                decoded("hello", 0x7000_0000, AddressType::Heap, 0x1050, 0x1100),
                decoded("world", 0x7000_0010, AddressType::Heap, 0x1050, 0x1100),
            ],
            ..Default::default()
        };
        let synth = get_synthetic_strings(&strings, &db());
        assert_eq!(texts(&synth), vec![(0x1050, "hello"), (0x1050, "world")]);
        assert!(synth[&0x1050].iter().all(|s| s.uses == vec![0x1050]));
    }

    #[test]
    fn function_has_each_string_once() {
        let strings = Strings {
            decoded_strings: vec![
                decoded("hello", 0x7000_0000, AddressType::Heap, 0x1050, 0x1100),
                decoded("hello", 0x7000_0010, AddressType::Heap, 0x1060, 0x1100),
                decoded("hello", 0x7000_0000, AddressType::Heap, 0x1250, 0x1100),
            ],
            ..Default::default()
        };
        let synth = get_synthetic_strings(&strings, &db());
        assert_eq!(texts(&synth), vec![(0x1050, "hello"), (0x1250, "hello")]);
        assert_eq!(synth[&0x1050][0].uses, vec![0x1050, 0x1060]);
    }

    #[test]
    fn string_that_a_routine_built_and_consumed_isnt_at_the_calls_to_the_routine() {
        let strings = Strings {
            stack_strings: vec![stack("kernel32.dll", &[0x1004], &[])],
            decoded_strings: vec![
                decoded("hello", 0x7000_0000, AddressType::Heap, 0x1050, 0x1100),
                decoded("hello", 0x7000_0000, AddressType::Heap, 0x1250, 0x1000),
                decoded("kernel32.dll", 0x7fff_0000, AddressType::Stack, 0x1250, 0x1000),
            ],
            ..Default::default()
        };
        let synth = get_synthetic_strings(&strings, &db());
        assert_eq!(texts(&synth), vec![(0x1004, "kernel32.dll"), (0x1050, "hello")]);
        assert_eq!(synth[&0x1004][0].uses, vec![0x1130, 0x1140]);
        assert_eq!(synth[&0x1050][0].uses, vec![0x1050, 0x1130, 0x1140]);
    }

    #[test]
    fn string_that_a_routine_built_and_returned_is_at_the_calls_to_the_routine() {
        let mut returned = decoded("hello", 0x7000_0000, AddressType::Heap, 0x1050, 0x1100);
        (returned.readers, returned.passed_to) = (vec![], vec![]);
        let strings = Strings {
            decoded_strings: vec![decoded("hello", 0x7000_0000, AddressType::Heap, 0x1100, 0x1100), returned],
            ..Default::default()
        };
        let synth = get_synthetic_strings(&strings, &db());
        assert_eq!(texts(&synth), vec![(0x1050, "hello"), (0x1110, "hello")]);
    }

    #[test]
    fn reused_global_buffer_is_at_the_writers() {
        let strings = Strings {
            decoded_strings: vec![
                decoded("secret key-xyz", 0x3000, AddressType::Global, 0x1100, 0x1100),
                decoded("secret key+abc", 0x3000, AddressType::Global, 0x1100, 0x1100),
            ],
            ..Default::default()
        };
        let synth = get_synthetic_strings(&strings, &db());
        assert_eq!(texts(&synth), vec![(0x1110, "secret key-xyz"), (0x1120, "secret key+abc")]);
        assert_eq!(synth[&0x1110][0].uses, vec![0x1130, 0x1140]);
        assert!(!synth[&0x1110][0].repeatable);
    }

    #[test]
    fn decoded_string_that_the_program_has_as_a_static_string_is_left_out() {
        let strings = Strings {
            stack_strings: vec![stack("kernel32.dll", &[0x1004], &[0x1064])],
            decoded_strings: vec![
                decoded("kernel32.dll", 0x7000_0000, AddressType::Heap, 0x1050, 0x1100),
                decoded("copied text", 0x7000_0100, AddressType::Heap, 0x1050, 0x1100),
                decoded("decoded text", 0x7000_0200, AddressType::Heap, 0x1050, 0x1100),
            ],
            ..Default::default()
        };
        let db = Db(db().0, db().1, vec![], vec!["kernel32.dll", "copied text"]);
        let synth = get_synthetic_strings(&strings, &db);
        assert_eq!(texts(&synth), vec![(0x1004, "kernel32.dll"), (0x1050, "decoded text")]);
        assert_eq!(synth[&0x1004][0].uses, vec![0x1064], "the stack string, which its function builds, stays as it is");
    }
}
