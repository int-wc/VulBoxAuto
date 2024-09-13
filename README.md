# VulBoxAuto
漏洞盒子批量提交2024，需要的参数有高德地图api，web服务的key，以及漏洞盒子登陆后的Cookie，提交漏洞时的Authorization，自己的User-agent，由于技术性问题，行业由模糊字典提供，新版本审核需要自性加上截图
命令形式：
python3 commit.py --user-agent-file User-Agent.txt --cookie-file Cookie.txt --authorization-file Authorization.txt --geo-api-key 你自己申请的key
