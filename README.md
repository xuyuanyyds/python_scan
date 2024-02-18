# python_scan

## 简介：

`使用python的socket来扫描主机端口，实现tcp全开和半开扫描、UDP扫描、ICMP扫描、Banner探测。`

查看帮助文档：

```
python scan.py -h
```

或者也可以：

```
python scan.py --help
```
![微信图片_20240218233711](https://github.com/xuyuanyyds/python_scan/assets/95127717/a8ade30c-a9f2-4c17-823c-997824d2564b)
## 安装依赖模块：

```
多线程、socket库、scrapy包等
pip install Argparse Scrapy threading ipaddress
```

## 可选择参数：

```
-h,--help 查看使用帮助 
-i,--ipaddr 扫描的ip地址
-p,--port 指定扫描端口，可以用,分隔或者-来指示扫描的端口区间范围
-sT                   TCP全开扫描
-sS                   TCP半开扫描
-sP                   ICMP ping 主机扫描
-sU                   UDP扫描
-sB                   banner探测
```

## 详细使用参数：

```
Scanning method方法就为：-sT、-sS、-sP、-sU、-sB
python nmap_self.py -i <IP> -p <port> <Scanning method> 
python nmap_self.py -i <IP> -p all <Scanning method>
```

## 使用样例：

```
python scan.py -i 192.168.146.181 -p 80,3306 -sT
```

### result：

![image-20240219001052504](https://github.com/xuyuanyyds/python_scan/assets/95127717/5e292dff-6aac-4c1c-88d7-1a128abf8519)


```
python scan.py -i 192.168.146.181 -p 80-90 -sT
```

### result：

![image-20240219001307547](https://github.com/xuyuanyyds/python_scan/assets/95127717/95b0a472-e5b1-4879-8ce0-2961fd34006c)


```
python scan.py -i 192.168.146.181 -p all -sT
```

### result：

![image-20240219001405826](https://github.com/xuyuanyyds/python_scan/assets/95127717/4aa18943-c4d2-42b1-96cf-3388f439b5eb)


```
python scan.py -i 192.168.146.181 -p 3306,3307 -sB
```

### result：

![image-20240219001632362](https://github.com/xuyuanyyds/python_scan/assets/95127717/e7e42ebc-3402-486e-9f54-a4a501d8446b)


