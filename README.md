# CHM
## 目錄結構
- libs/*: 所有其他lib Crate存放處
- ./*: 所有可執行的Crate
## chm tools 補齊
### bash
#### `~/.bashrc`
```shell
# 啟用系統補全
if [ -f /etc/bash_completion ]; then
  source /etc/bash_completion
fi

# 自動載入~/.bash_completion.d/下所有補齊文件
if [ -d "$HOME/.bash_completion.d" ]; then
  for bcfile in "$HOME"/.bash_completion.d/*.bash; do
    [ -r "$bcfile" ] && source "$bcfile"
  done
fi
```
添加完成之後再執行`source ~/.bashrc`
### zsh
#### `~/.zshrc`
```shell
fpath+=(~/.zsh/completion)
autoload -Uz compinit && compinit
```
添加完成之後再執行`source ~/.zshrc`

### fish
重啟Shell就會自動讀取

### PowerShell
#### 執行以下指令
```powershell
notepad $PROFILE
```
添加以下內容
```powershell
Import-Module cargo-chm
```
