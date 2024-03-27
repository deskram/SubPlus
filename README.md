#                         SubPlus
PY DEV DeskRam «Ali» https://t.me/deskram

# Installation 🛠️
# Windows
```shell
git clone https://github.com/deskram/SubPlus.git
```
```shell
cd SubPlus
```
* on Powershell: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force`
* setup Virtualenv: `pip install virtualenv`
* Windows Powershell: `virtualenv SubPlus`
* Windows Powershell: `.\SubPlus\Scripts\activate.ps1`
* Install Requirements `pip install -r requirements.txt`
* Windows Powershell: `py subplus.py -d domain.com` or `python subplus.py -d domain.com`
```python
python subplus.py -d domain.com -su subs.txt
```
```python
python subplus.py -d domain.com -su subs.txt -s service.txt -r subs.txt -es true
```
#
#
# Linux
```shell
git clone https://github.com/deskram/SubPlus.git
```
```shell
cd SubPlus
```
```shell
pip install -r requirements.txt
```
```shell
cp subplus.py /usr/local/bin/subplus
```
```shell
chmod +x /usr/local/bin/subplus
```
```shell
subplus -h
```
```shell
subplus -d domain.com -su subs.txt
```
```bash
subplus -d domain.com -su subs.txt -s service.txt -r subs.txt -es true
```
### 📢 Warning 
*This tool is only for educational purpose. If you use this tool for other purposes except education we will not be responsible in such cases.*
