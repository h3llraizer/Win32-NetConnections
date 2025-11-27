# Win32-NetConnections

Simple demonstration of enumerating TCP-UDP/IP connections on a windows machine and mapping the connections to PIDs & Process Names.

## 🚀 Features
- Display TCP and/or UDP connections with their process information

## 📦 Requirements
- PcapPlusPlus (https://github.com/seladb/PcapPlusPlus)

## ❗Heads up / Warning
- The UDP connection mapper object isn't able to enumerate remote-ip & remote-port due to limitation of the current API function being used - fixing soon