## ccs-panel

## Features
- Centrally manage Claude Code provider configurations for different SSH servers from your local machine.
- Developed based on [cc-switch](https://github.com/farion1231/cc-switch/) (commit: 395783e22a0bcd530ab883b9d8784d537c5ffac3); data format is compatible with cc-switch.

## Usage
**请注意，由于cc-switch存储架构更新，当使用ccs-panel添加新的服务器的时候，需要显式指定sqlite3可执行文件路径，自动检测功能可能无法正常管理。**

- Build from source

```bash
# Clone the repository
git clone https://github.com/FanBB2333/ccs-panel.git
cd ccs-panel

pnpm build release
```
<!-- - Binary Files -->


## Interface Showcase
- Main Interface    ![](assets/ccs-panel/main.png)
- Add Server Interface    ![](assets/ccs-panel/add-server.png)

## WARNING
This project is currently under active iteration.


## Acknowledgements
- [cc-switch](https://github.com/farion1231/cc-switch)
- [CC-Switch-Web](https://github.com/Laliet/CC-Switch-Web)

