use cargo_metadata::{MetadataCommand, TargetKind};
use clap::{
    Command, CommandFactory, Parser, Subcommand, ValueHint,
    builder::{PossibleValue, PossibleValuesParser},
    value_parser,
};
use clap_complete::{Shell as ClapShell, generate, generate_to};
use duct::cmd;
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    process::exit,
};
const FRONTEND_PACKAGER: &str = "pnpm";
const FRONTEND_DIR: &str = "frontend";
const ALIAS: &str = "chm";

#[derive(Parser)]
#[command(
    name = ALIAS,
    bin_name = ALIAS,
    author,
    version,
    about,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// 產生shell completion 腳本
    Completions {
        /// 指定要生成哪種 shell 的 completion
        #[arg(long, value_parser = value_parser!(ClapShell))]
        shell: ClapShell,
        /// output directory (預設: "./completions")
        #[arg(long, default_value = "completions",value_hint = ValueHint::AnyPath)]
        out_dir: String,
    },
    /// 安裝補全腳本到使用者目錄
    InstallCompletions {
        /// 要安裝哪個 shell 的補全
        #[arg(value_enum)]
        shell: ClapShell,
    },
    /// 建置前端
    Frontend {
        #[command(subcommand)]
        action: FrontendAction,
    },
    /// 建置後端
    Backend {
        #[command(subcommand)]
        action: BackendAction,
    },
    /// 建置全部
    Build,
    /// 執行全部
    Run,
    /// 測試
    Test,
    #[command(name = "help", about = "顯示自訂的說明，包含所有子命令清單")]
    Help {
        /// 想要查詢的子命令名稱（可選）
        subcmd: Option<String>,
    },
}

#[derive(Subcommand)]
enum FrontendAction {
    /// 安裝依賴
    Install,
    /// 建置
    Build,
    /// 開發模式
    Dev,
}

#[derive(Subcommand)]
enum BackendAction {
    /// 建置release版本
    Build {
        #[arg(
            short = 'b',
            long = "bin",
            value_name = "BIN",
            conflicts_with = "package"
        )]
        bin: Option<String>,
        /// 要編譯哪些 package（可重複指定多個)；不指定就用 `--workspace`
        #[arg(short='p', long="package", value_name="PKG", num_args=1.., conflicts_with = "bin")]
        package: Vec<String>,
    },
    /// Debug版本
    Debug {
        #[arg(
            short = 'b',
            long = "bin",
            value_name = "BIN",
            conflicts_with = "package"
        )]
        bin: Option<String>,
        /// 要編譯哪些 package（可重複指定多個)；不指定就用 `--workspace`
        #[arg(short='p', long="package", value_name="PKG", num_args=1.., conflicts_with = "bin")]
        package: Vec<String>,
    },
    /// 測試
    Test {
        #[arg(
            short = 'b',
            long = "bin",
            value_name = "BIN",
            conflicts_with = "package"
        )]
        bin: Option<String>,
        /// 要編譯哪些 package（可重複指定多個)；不指定就用 `--workspace`
        #[arg(short='p', long="package", value_name="PKG", num_args=1.., conflicts_with = "bin")]
        package: Vec<String>,
    },
    /// 執行
    Run {
        #[arg(
            short = 'b',
            long = "bin",
            value_name = "BIN",
            conflicts_with = "package"
        )]
        bin: Option<String>,
        /// 要編譯哪些 package（可重複指定多個)；不指定就用 `--workspace`
        #[arg(short='p', long="package", value_name="PKG", num_args=1.., conflicts_with = "bin")]
        package: Vec<String>,
    },
    /// 清除編譯產物
    Clean,
}

fn main() {
    let cli = Cli::parse();
    let mut app = Cli::command();
    match cli.command {
        Commands::Help { subcmd } => {
            if let Some(name) = subcmd {
                if let Some(sub) = app.find_subcommand_mut(&name) {
                    sub.print_long_help().unwrap();
                } else {
                    eprintln!("Unknown subcommand: {}", name);
                }
            } else {
                app.print_long_help().unwrap();
            }
        }
        Commands::Completions { shell, out_dir } => {
            generate_completions(shell, &out_dir);
        }
        Commands::InstallCompletions { shell } => {
            install_to_user_dir(shell);
        }
        Commands::Backend { action } => {
            run_backend(action);
        }
        Commands::Frontend { action } => {
            run_frontend(action);
        }
        Commands::Build => unimplemented!("Build action not implemented"),
        Commands::Run => unimplemented!("Run action not implemented"),
        Commands::Test => unimplemented!("Test action not implemented"),
    }
}

fn run_frontend(action: FrontendAction) {
    let mut args = Vec::new();
    match action {
        FrontendAction::Install => {
            args.push("install");
        }
        FrontendAction::Build => {
            args.push("build");
        }
        FrontendAction::Dev => {
            args.push("dev");
        }
    }
    run_cmd(FRONTEND_PACKAGER, &args, FRONTEND_DIR);
}

fn run_backend(action: BackendAction) {
    let mut args = Vec::new();
    let mut targets = Vec::new();

    match action {
        BackendAction::Build {
            ref bin,
            ref package,
        } => {
            let (base_args, base_targets) = process_package_and_bin(bin.as_ref(), package, "build");
            args.extend(base_args);
            targets.extend(base_targets);
            args.push("--release");
        }
        BackendAction::Debug {
            ref bin,
            ref package,
        } => {
            let (base_args, base_targets) = process_package_and_bin(bin.as_ref(), package, "build");
            args.extend(base_args);
            targets.extend(base_targets);
        }
        BackendAction::Test {
            ref bin,
            ref package,
        } => {
            let (base_args, base_targets) = process_package_and_bin(bin.as_ref(), package, "test");
            args.extend(base_args);
            targets.extend(base_targets);
        }
        BackendAction::Run {
            ref bin,
            ref package,
        } => {
            let (base_args, base_targets) = process_package_and_bin(bin.as_ref(), package, "run");
            args.extend(base_args);
            targets.extend(base_targets);
        }
        BackendAction::Clean => {
            args.push("clean");
        }
    }
    if matches!(action, BackendAction::Run { .. }) {
        if targets.len() == 1 {
            args.push("--package");
            args.push(&targets[0]);
        } else if !targets.is_empty() {
            eprintln!(
                "❌ `run` 一次只能指定一個 binary package，當前指定: {:?}",
                targets
            );
            exit(1);
        } else if !args.iter().any(|arg| arg == &"--bin") {
            eprintln!("❌ `run` 必須指定要執行的單一 binary (--bin 或 --package)");
            exit(1);
        }
    } else if targets.is_empty() {
        args.push("--workspace");
    } else {
        args.push("--package");
        args.extend(targets.iter().map(String::as_str));
    }
    run_cmd("cargo", &args, ".");
}

fn run_cmd<S: AsRef<str>>(program: S, args: &[&str], cwd: &str) {
    let expression = if cfg!(target_os = "windows") {
        let full_cmd = std::iter::once(program.as_ref())
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        cmd(
            "powershell",
            &[
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &full_cmd,
            ],
        )
    } else {
        cmd(program.as_ref(), args)
    };

    if let Err(e) = expression.dir(cwd).stderr_to_stdout().run() {
        eprintln!("❌ `{}` {:?} 失敗: {}", program.as_ref(), args, e);
        exit(1);
    }
}

fn workspace_members() -> (Vec<String>, Vec<String>) {
    let meta = MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("無法讀取 cargo metadata");
    let (package_names, bin_names): (Vec<_>, Vec<_>) = meta
        .workspace_members
        .iter()
        .filter_map(|member_id| meta.packages.iter().find(|p| &p.id == member_id))
        .flat_map(|package| {
            let package_name = package.name.clone();
            let bin_targets = package
                .targets
                .iter()
                .filter(|target| target.kind.iter().any(|k| matches!(k, TargetKind::Bin)))
                .map(|target| target.name.clone())
                .collect::<Vec<_>>();
            Some((package_name, bin_targets))
        })
        .unzip();

    let bin_names = bin_names.into_iter().flatten().collect();

    (package_names, bin_names)
}

fn gen_comp() -> Command {
    let (packages, bins) = workspace_members();
    let possibles_packages: Vec<PossibleValue> = packages
        .into_iter()
        .map(|s| PossibleValue::new(Box::leak(s.into_boxed_str()) as &str))
        .collect();
    let possibles_bins: Vec<PossibleValue> = bins
        .into_iter()
        .map(|s| PossibleValue::new(Box::leak(s.into_boxed_str()) as &str))
        .collect();
    let mut cmd = Cli::command();
    cmd = cmd.mut_subcommand("backend", |sc| {
        sc.mut_subcommand("build", |sub| {
            sub.mut_arg("package", |arg| {
                arg.value_parser(PossibleValuesParser::new(possibles_packages.clone()))
            })
            .mut_arg("bin", |arg| {
                arg.value_parser(PossibleValuesParser::new(possibles_bins.clone()))
            })
        })
        .mut_subcommand("debug", |sub| {
            sub.mut_arg("package", |arg| {
                arg.value_parser(PossibleValuesParser::new(possibles_packages.clone()))
            })
            .mut_arg("bin", |arg| {
                arg.value_parser(PossibleValuesParser::new(possibles_bins.clone()))
            })
        })
        .mut_subcommand("test", |sub| {
            sub.mut_arg("package", |arg| {
                arg.value_parser(PossibleValuesParser::new(possibles_packages.clone()))
            })
            .mut_arg("bin", |arg| {
                arg.value_parser(PossibleValuesParser::new(possibles_bins.clone()))
            })
        })
        .mut_subcommand("run", |sub| {
            sub.mut_arg("package", |arg| {
                arg.value_parser(PossibleValuesParser::new(possibles_packages.clone()))
            })
            .mut_arg("bin", |arg| {
                arg.value_parser(PossibleValuesParser::new(possibles_bins.clone()))
            })
        })
    });
    cmd
}

fn generate_completions(shell: ClapShell, out_dir: &str) {
    let mut cmd = gen_comp();
    // let bin_name = format!("cargo-{}", env!("CARGO_PKG_NAME"));
    let bin_name = format!("cargo-{}", ALIAS);
    let out_path = PathBuf::from(out_dir);
    std::fs::create_dir_all(&out_path).unwrap_or_else(|e| {
        eprintln!("❌ 建立目錄失敗: {}", e);
        exit(1)
    });

    if shell == ClapShell::PowerShell {
        let file_path = out_path.join(format!("{}.psm1", bin_name));
        let file = File::create(&file_path).unwrap_or_else(|e| {
            eprintln!("❌ 無法創建 {}: {}", file_path.display(), e);
            exit(1)
        });
        let mut buf = BufWriter::new(file);
        generate(ClapShell::PowerShell, &mut cmd, &bin_name, &mut buf);
        println!(
            "✅ 已生成 PowerShell (psm1) completion 到 `{}`",
            file_path.display()
        );
    } else {
        generate_to(shell, &mut cmd, &bin_name, &out_path).unwrap_or_else(|e| {
            eprintln!("❌ 無法生成 completion: {}", e);
            exit(1);
        });
        println!("✅ 已生成 {:?} completion 到 `{}`", shell, out_dir);
    }
}

fn install_to_user_dir(shell: ClapShell) {
    use clap_complete::generate;
    use dirs::home_dir;
    use std::{fs, io::BufWriter, path::PathBuf, process::exit};

    let bin_name = format!("cargo-{}", ALIAS);
    if shell == ClapShell::PowerShell {
        let home = home_dir().unwrap_or_else(|| {
            eprintln!("❌ 無法取得使用者目錄");
            exit(1)
        });

        #[allow(unused_mut)]
        let mut module_dirs: Vec<PathBuf> =
            vec![home.join("Documents/PowerShell/Modules").join(&bin_name)];
        #[cfg(windows)]
        module_dirs.push(
            home.join("Documents/WindowsPowerShell/Modules")
                .join(&bin_name),
        );

        for target_dir in module_dirs {
            if let Err(e) = fs::create_dir_all(&target_dir) {
                eprintln!("❌ 無法創建目錄 {}: {}", target_dir.display(), e);
                exit(1);
            }

            let file_path = target_dir.join(format!("{}.psm1", bin_name));
            let file = fs::File::create(&file_path).unwrap_or_else(|e| {
                eprintln!("❌ 無法創建文件 {}: {}", file_path.display(), e);
                exit(1);
            });
            let mut buf = BufWriter::new(file);
            let mut cmd = Cli::command();
            generate(ClapShell::PowerShell, &mut cmd, &bin_name, &mut buf);
            let custom_content = r#"
function Invoke-CargoChm {
    cargo run -p xtask -- @args
}
Set-Alias -Name "cargo-chm" -Value Invoke-CargoChm
"#;

            writeln!(buf, "{}", custom_content).unwrap_or_else(|e| {
                eprintln!("❌ 無法寫入自定義內容到文件 {}: {}", file_path.display(), e);
                exit(1);
            });

            println!("✅ 已安装 PowerShell 補全到 {}", file_path.display());
        }

        println!("   重新打開或 reload 你的 PowerShell，即可生效");
        return;
    }

    let (mut target_dir, filename) = match shell {
        ClapShell::Bash => (
            home_dir().unwrap().join(".bash_completion.d"),
            format!("{}.bash", bin_name),
        ),
        ClapShell::Zsh => (
            home_dir().unwrap().join(".zsh/completion"),
            format!("_{}", bin_name),
        ),
        ClapShell::Fish => (
            home_dir().unwrap().join(".config/fish/completions"),
            format!("{}.fish", bin_name),
        ),
        ClapShell::Elvish => (
            home_dir().unwrap().join(".config/elvish/rc.d"),
            format!("{}.elvish", bin_name),
        ),
        _ => unreachable!(),
    };

    fs::create_dir_all(&target_dir).unwrap_or_else(|e| {
        eprintln!("❌ 無法創建目錄 {}: {}", target_dir.display(), e);
        exit(1);
    });
    target_dir.push(&filename);

    let file = fs::File::create(&target_dir).unwrap_or_else(|e| {
        eprintln!("❌ 無法創建文件 {}: {}", target_dir.display(), e);
        exit(1);
    });
    let mut buf = BufWriter::new(file);
    let mut cmd = gen_comp();
    generate(shell, &mut cmd, &bin_name, &mut buf);

    println!("✅ 已安装 {} 補全到 {}", bin_name, target_dir.display());
    println!("   重新打開或 reload 你的 shell 即可生效");
}

fn process_package_and_bin<'a>(
    bin: Option<&'a String>,
    package: &'a [String],
    command: &'a str,
) -> (Vec<&'a str>, Vec<String>) {
    let mut args = vec![command];
    let mut targets = Vec::new();

    if let Some(bin_name) = bin {
        args.extend(vec!["--bin", bin_name]);
    } else {
        targets.extend(package.iter().cloned());
    }

    (args, targets)
}
