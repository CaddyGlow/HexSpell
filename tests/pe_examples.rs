#![cfg(all(feature = "pe", feature = "write"))]
#[path = "../examples/support/mod.rs"]
#[allow(dead_code)]
mod support;
use hexspell::pe::build::Target;
#[test]
fn generated_acceptance_images_have_expected_tables() {
    for target in [Target::X86, Target::X64] {
        let hello = support::hello(target).unwrap();
        assert!(hello.tls().unwrap().is_some());
        assert!(hello.resources().unwrap().is_some());
        let resources = hexspell::pe::resource::ResourceDirectoryOwned::from_pe(&hello).unwrap();
        let icon = resources
            .icon(&hexspell::pe::resource::ResourceKey::Id(1), 1033)
            .unwrap();
        assert_eq!(icon.images.len(), 1);
        assert_eq!(hello.buffer, support::hello(target).unwrap().buffer);
        assert!(support::hello_with_tls(target, false)
            .unwrap()
            .tls()
            .unwrap()
            .is_some());
        assert!(support::hello_with_options(target, true, true).is_ok());
        assert_eq!(hello.imports().unwrap().dlls.len(), 2);
        assert!(!hello.base_relocations().unwrap().is_empty());
        let dll = support::dll(target).unwrap();
        let exports = dll.exports().unwrap().unwrap();
        assert_eq!(
            exports
                .named
                .iter()
                .map(|row| (row.name.as_str(), row.ordinal))
                .collect::<Vec<_>>(),
            vec![("Add", 1), ("GetGreeting", 2)]
        );
        assert_eq!(exports.functions.len(), 3);
        assert_eq!(exports.ordinal_only_exports().len(), 1);
        assert_eq!(dll.buffer, support::dll(target).unwrap().buffer);
    }
}
