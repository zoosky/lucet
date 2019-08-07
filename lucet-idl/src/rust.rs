mod cursor;

use crate::error::IDLError;
use crate::pretty_writer::PrettyWriter;
use crate::{
    AliasDatatype, DatatypeVariant, EnumDatatype, Function, MemArea, Module, Package,
    StructDatatype,
};
pub use cursor::{
    render_tuple, RustFunc, RustIdiomArg, RustIdiomRet, RustName, RustTupleSyntax, RustTypeName,
};
use heck::SnakeCase;
use std::io::Write;

/// Generator for the Rust backend
pub struct RustGenerator {
    pub w: PrettyWriter,
}

impl RustGenerator {
    pub fn new(w: Box<dyn Write>) -> Self {
        Self {
            w: PrettyWriter::new(w),
        }
    }

    pub fn generate_guest(&mut self, package: &Package) -> Result<(), IDLError> {
        for module in package.modules() {
            self.w
                .writeln(format!("mod {} {{", module.rust_name()))
                .indent();
            self.generate_datatypes(&module)?;

            self.w
                .writeln("mod abi {")
                .indent()
                .writeln(format!("#[link(wasm_import_module=\"{}\")]", module.name()))
                .writeln("extern \"C\" {")
                .indent();
            for f in module.functions() {
                self.guest_abi_import(&f)?;
            }
            self.w.eob().writeln("}").eob().writeln("}");

            for f in module.functions() {
                self.guest_idiomatic_def(&f)?;
            }

            self.w.eob().writeln("}");
        }
        Ok(())
    }

    pub fn generate_host(&mut self, package: &Package) -> Result<(), IDLError> {
        for module in package.modules() {
            self.w
                .writeln(format!("mod {} {{", module.rust_name()))
                .indent();
            self.generate_datatypes(&module)?;

            self.host_trait_definition(&module)?;

            self.w
                .writeln("use lucet_runtime::{lucet_hostcalls, lucet_hostcall_terminate};");
            self.w.writeln("lucet_hostcalls! {").indent();
            for func in module.functions() {
                self.host_abi_definition(&func)?;
            }
            self.w.eob().writeln("}");

            self.host_ensure_linked(&module);

            self.w
                .eob()
                .writeln(format!("}} // end module {}", module.rust_name()));
        }
        Ok(())
    }

    fn generate_datatypes(&mut self, module: &Module) -> Result<(), IDLError> {
        for dt in module.datatypes() {
            match dt.variant() {
                DatatypeVariant::Struct(s) => self.gen_struct(&s)?,
                DatatypeVariant::Alias(a) => self.gen_alias(&a)?,
                DatatypeVariant::Enum(e) => self.gen_enum(&e)?,
                DatatypeVariant::Atom { .. } => {}
            }
        }
        Ok(())
    }

    fn gen_alias(&mut self, alias: &AliasDatatype) -> Result<(), IDLError> {
        self.w.writeln(format!(
            "pub type {} = {};",
            alias.rust_type_name(),
            alias.to().rust_type_name()
        ));

        gen_testcase(&mut self.w, &alias.name().to_snake_case(), move |w| {
            w.writeln(format!(
                "assert_eq!({}, ::std::mem::size_of::<super::{}>());",
                alias.mem_size(),
                alias.rust_type_name()
            ));
            Ok(())
        })?;
        Ok(())
    }

    fn gen_struct(&mut self, struct_: &StructDatatype) -> Result<(), IDLError> {
        self.w
            .writeln("#[repr(C)]")
            .writeln(format!("pub struct {} {{", struct_.rust_type_name()));

        let mut w = self.w.new_block();
        for m in struct_.members() {
            w.writeln(format!(
                "pub {}: {},",
                m.rust_name(),
                m.type_().rust_type_name(),
            ));
        }

        self.w.writeln("}");

        gen_testcase(&mut self.w, &struct_.name().to_snake_case(), |w| {
            w.writeln(format!(
                "assert_eq!({}, ::std::mem::size_of::<super::{}>());",
                struct_.mem_size(),
                struct_.rust_type_name(),
            ));

            for m in struct_.members() {
                w.writeln(format!(
                    "assert_eq!({}, {{ let base = ::std::ptr::null::<super::{}>(); unsafe {{ (&(*base).{}) as *const _ as usize }} }});",
                    m.offset(), struct_.rust_type_name(), m.rust_name(),
                ));
            }
            Ok(())
        })?;
        Ok(())
    }

    // Enums generate both a specific typedef, and a traditional C-style enum
    // The typedef is required to use a native type which is consistent across all architectures
    fn gen_enum(&mut self, enum_: &EnumDatatype) -> Result<(), IDLError> {
        self.w
            .writeln("#[repr(C)]")
            .writeln("#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]")
            .writeln(format!("pub enum {} {{", enum_.rust_type_name()));

        let mut w = self.w.new_block();
        for v in enum_.variants() {
            w.writeln(format!("{},", v.rust_name()));
        }

        self.w.writeln("}");

        gen_testcase(&mut self.w, &enum_.name().to_snake_case(), |w| {
            w.writeln(format!(
                "assert_eq!({}, ::std::mem::size_of::<super::{}>());",
                enum_.mem_size(),
                enum_.rust_type_name(),
            ));
            Ok(())
        })?;
        Ok(())
    }
    fn guest_abi_import(&mut self, func: &Function) -> Result<(), IDLError> {
        let mut arg_syntax = Vec::new();
        for a in func.args() {
            arg_syntax.push(format!("{}: {}", a.rust_name(), a.type_().rust_type_name()));
        }

        let ret_syntax = func
            .rets()
            .map(|r| r.type_().rust_type_name())
            .rust_tuple_syntax("()");

        self.w.writeln("#[no_mangle]").writeln(format!(
            "pub fn {}({}) -> {};",
            func.rust_name(),
            arg_syntax.join(", "),
            ret_syntax
        ));

        Ok(())
    }

    fn guest_idiomatic_def(&mut self, func: &Function) -> Result<(), IDLError> {
        let name = func.rust_name();
        let idiom_args = func.rust_idiom_args();
        let idiom_rets = func.rust_idiom_rets();

        let idiom_arg_syntax = idiom_args
            .iter()
            .map(|a| a.arg_declaration())
            .collect::<Vec<_>>()
            .join(", ");
        let idiom_ret_syntax = format!(
            "Result<{},()>",
            idiom_rets
                .iter()
                .map(|r| r.ret_declaration())
                .rust_tuple_syntax("()")
        );

        self.w
            .writeln(format!(
                "pub fn {}({}) -> {} {{",
                name, idiom_arg_syntax, idiom_ret_syntax
            ))
            .indent();
        for a in idiom_args.iter() {
            self.w.writelns(&a.guest_abi_args());
        }
        for r in idiom_rets.iter() {
            self.w.writelns(&r.guest_abi_args());
        }

        self.w.writeln(format!(
            "let {} = unsafe {{ abi::{}({}) }};",
            func.rets().map(|r| r.rust_name()).rust_tuple_syntax("_"),
            name,
            func.args()
                .map(|a| a.rust_name())
                .collect::<Vec<_>>()
                .join(", ")
        ));

        for r in idiom_rets.iter() {
            self.w.writeln(r.guest_from_abi_call());
        }

        self.w.writeln(format!(
            "Ok({})",
            idiom_rets.iter().map(|r| r.name()).rust_tuple_syntax("()")
        ));
        self.w.eob().writeln("}");
        Ok(())
    }

    fn host_abi_definition(&mut self, func: &Function) -> Result<(), IDLError> {
        let mut args = vec![format!("&mut vmctx")];
        for a in func.args() {
            args.push(format!(
                "{}: {}",
                a.rust_name().to_snake_case(),
                a.type_().rust_type_name(),
            ));
        }

        let abi_rettype = func
            .rets()
            .map(|r| r.type_().rust_type_name())
            .rust_tuple_syntax("()");

        self.w
            .writeln("#[no_mangle]")
            .writeln(format!(
                "// Wasm func {}::{}",
                func.module().name(),
                func.rust_name()
            ))
            .writeln(format!(
                "pub unsafe extern \"C\" fn {}({},) -> {} {{",
                func.host_func_name(),
                args.join(", "),
                abi_rettype
            ));

        self.w.indent();

        let trait_type_name = func.module().rust_type_name();

        self.w.writeln(format!(
            "fn inner(heap: &mut [u8], obj: &mut dyn {}, {}) -> Result<{},()> {{",
            trait_type_name,
            func.args()
                .map(|a| format!("{}: {}", a.rust_name(), a.type_().rust_type_name(),))
                .collect::<Vec<String>>()
                .join(", "),
            abi_rettype,
        ));
        self.w.indent();
        {
            let idiom_args = func.rust_idiom_args();
            let idiom_rets = func.rust_idiom_rets();

            for a in idiom_args.iter() {
                self.w.writelns(&a.host_unpack_to_abi());
            }
            for r in idiom_rets.iter() {
                self.w.writelns(&r.host_unpack_to_abi());
            }
            self.w.writeln(format!(
                "let {} = obj.{}({})?;",
                idiom_rets.iter().map(|r| r.name()).rust_tuple_syntax("_"),
                func.rust_name(),
                idiom_args
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
            for r in idiom_rets.iter() {
                self.w.writeln(r.host_unpack_from_abi());
            }
            self.w.writeln(format!(
                "Ok({})",
                func.rets()
                    .map(|r| r.name().to_string())
                    .rust_tuple_syntax("()")
            ));
        }
        self.w.eob().writeln("}");

        self.w.writeln(format!(
                "let mut ctx: ::std::cell::RefMut<Box<{typename}>> = vmctx.get_embed_ctx_mut::<Box<{typename}>>();",
                typename =trait_type_name
            ));
        self.w.writeln("let mut heap = vmctx.heap_mut();");
        self.w.writeln(format!(
                "match inner(&mut *heap, &mut **ctx, {}) {{ Ok(v) => v, Err(e) => lucet_hostcall_terminate!(\"FIXME\"), }}",
                func.args()
                    .map(|a| a.name().to_owned())
                    .collect::<Vec<String>>()
                    .join(", "),
            ));
        self.w.eob().writeln("}");

        Ok(())
    }

    fn host_trait_definition(&mut self, module: &Module) -> Result<(), IDLError> {
        self.w
            .writeln(format!("pub trait {} {{", module.rust_type_name()))
            .indent();
        for func in module.functions() {
            let mut args = func
                .rust_idiom_args()
                .iter()
                .map(|a| a.arg_value())
                .collect::<Vec<_>>();
            args.insert(0, "&mut self".to_owned());
            let rets = func
                .rust_idiom_rets()
                .iter()
                .map(|a| a.name())
                .rust_tuple_syntax("()");

            self.w.writeln(format!(
                "fn {}({}) -> {};",
                func.rust_name(),
                args.join(", "),
                format!("Result<{},()>", rets),
            ));
        }

        self.w.eob().writeln("}");

        Ok(())
    }

    fn host_ensure_linked(&mut self, module: &Module) {
        self.w.writeln("pub fn ensure_linked() {").indent();
        self.w.writeln("unsafe {").indent();
        for func in module.functions() {
            self.w.writeln(format!(
                "::std::ptr::read_volatile({} as *const extern \"C\" fn());",
                func.host_func_name(),
            ));
        }
        self.w.eob().writeln("}");
        self.w.eob().writeln("}");
    }
}

fn gen_testcase<F>(w: &mut PrettyWriter, name: &str, f: F) -> Result<(), IDLError>
where
    F: FnOnce(&mut PrettyWriter) -> Result<(), IDLError>,
{
    w.writeln("#[cfg(test)]")
        .writeln(format!("mod {} {{", name));
    let mut ww = w.new_block();
    ww.writeln("#[test]").writeln("fn test() {");
    let mut www = ww.new_block();
    f(&mut www)?;
    ww.writeln("}");
    w.writeln("}");
    Ok(())
}
