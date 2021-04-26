using System;
using System.Collections;
using System.Collections.Generic;
using Microsoft.Win32;
using static System.Convert;
using static System.Net.NetworkInformation.NetworkInterface;
using static System.Net.NetworkInformation.NetworkInterfaceType;
using static System.Net.Sockets.AddressFamily;
using static System.Security.Principal.WindowsBuiltInRole;
using static System.Security.Principal.WindowsIdentity;
using static System.Text.Encoding;
using System.DirectoryServices;
using System.Security.Principal;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;


namespace PSeeLibrary
{
    public static class PSeeMain
    {
        static Dictionary<int, String> _badmin = new Dictionary<int, String>() { { 0, "Elevate without prompting" }, { 1, "Prompt for credentials on the secure desktop" }, { 2, "Prompt for consent on the secure desktop" }, { 3, "Prompt for credentials" }, { 4, "Prompt for consent" }, { 5, "(Default) = Prompt for consent for non - Windows binaries" } };
        static Dictionary<int, String> _uadmin = new Dictionary<int, String>() { { 0, "Automatically deny elevation requests" }, { 1, "Prompt for credentials on the secure desktop" }, { 2, "Dont Know" }, { 3, "Prompt for credentials" } };
        static Dictionary<int, String> _uaclua = new Dictionary<int, String>() { { 0, "Disabled" }, { 1, "Run All Administrators in approval mode" } };
        static List<string> _avlist = new List<string>() { "IGMKrTdvWzN1AUorxFanKg==", "OPMYMg1Ocv7ojYfjpxAg8A==", "F+Cr91DJGEfpNpFmqKKesQ==", "QrdQ5ISOJynCj7Wsf3ZH3w==", "2Qoqcjo24vHr2bC/ZKaq6g==", "/QdqsHHDx1GcZQNcPW1IUA==", "eJGeaAR++mY3F/pA1/zTMg==", "IaP+GhAUlhQJuBmTW/jkIQ==", "XfwcxoygaeEr/e1zNF3OAw==", "u3beTulLQGm9Xzflk1L0wQ==", "O3q4lAalClD18AHZC3f7bg==", "Imzn4lx4CO8rjnJm/jfThQ==", "4/H7p/A+Dmzgka2V/POlGQ==", "1dquL8rQNWu7BtYniOkYIQ==", "Mg+G9g8lRZulVQ4ACyw5KQ==", "tmEYQSX6jm4fAv3f0MFx5g==", "EhwNMX/RAOcZSI1afVKwNQ==", "LS1J3Snj2VLC46UduPOxJQ==", "mdy7ytIZLZlnxDEhEgPPgg==", "EJjBzIXOV55NQY9rKqCqjQ==", "7SHSwuWL9xiAxcDrtmg9kQ==", "F4CN2ZDovHwuBqZASxFqlg==", "mD+eOAIpqEGAHh9OgDoprw==", "fT3cJqqgLYqZVCk4M8aNSg==", "o6g3h2Tndcvcaf/7/WohIA==", "zwfL7uhONIsdGohM1PWcCQ==", "UUJdXHFWJkYJph76GkuaCA==", "8p2fWhLxTiLrMTVOAECVPQ==", "WaAKBSVC/BHCw4TeOBdKVw==", "0QvYzhVQCc9ug3bxI7Nt7A==", "NGNI/izLucq9oiWtXmmjuQ==", "hZymt5+q/yH32ST4KonPHw==", "dTaXZsyhhraVJKCCl3GrYg==", "dTaXZsyhhraVJKCCl3GrYg==", "5lUrfyoeDqarajqDOMNgDw==", "H3GgXSedDADLxSyIrJRqvQ==", "dXSnI8zA70PE489tGptJIA==", "pEURFg7gbD32c7l0hJ5OYQ==", "6REIBL2Y77XQ7N+5ZSJzwg==", "9cPIXvkeBQBg86LXXoYBrw==", "e3vCUS7h/tzXa9xokm1Pew==", "9nvf+oZjWohzOJiFkg1GjQ==", "nufpl8N6TggAjTvq3Pypmw==", "mjTKUTMr89Jj+Vzjx3LO0g==", "orMAkRm4EUPmBVxPoGeDYA==", "q7/qTnmLo+Xz1Samo5Nz0A==", "wN7+i4R59oZDMyTYqyWAMw==", "uQhOdXIhyciAcgCeEV3OsA==", "yKrMb5wUCj5FGUk2cYoesA==", "/ruj6HqHM0KpYwJPRxPnCA==", "+2jUim8m+3pxy5TWhDvsvw==", "1DLtSFcToiDWzi3ZLsz/JQ==", "4Cyi5zl+/0VuS7fe8X8Udw==", "fdolXMV0E2+AL7BbeMXEAA==", "a8M+HcEtgjDdSp655SjLLQ==", "+BujJZk/Z8Upt8wkcUlaVQ==", "kod4OzjmfSqwe45sculpig==", "33I1E5ZZbhORL3BEcgKD2Q==", "SNh78sX1aS4cebKBxNUH8A==", "4hmqeQAPzoSwPfqEeIPxUg==", "NvP4vUtK0ytxIO5F7eSY9g==", "Bn3Jy5iVWHs0xp1IJuYLWA==", "Bn3Jy5iVWHs0xp1IJuYLWA==", "g0y1S2G77Z1ClsmV5MXYsg==", "LwwRUMVm71autfaUHteWag==", "ixCIYTDZt9/2gKLiDzdM5A==", "8GcI4/Yn+rAwfnptFPhR0g==", "W+EI6fsUtptXx98ITcEClQ==", "usRDpEoxqRsyp8sV+hwDMw==", "MyHSvycV/0e5M5ehT6+mQg==", "oNoEPDUfPLmPOoJUu3H07A==", "a8EwtsBsCXdwOcddE1pK4g==", "aCACKAySHDJaOFjvd/sTvA==", "2gTliSiUsG/809ExnGEorw==", "0jnM/fj4DroY/bdkDyyKow==", "WJh50CSteyIncmg+CP2POQ==", "VqlBT6Vm5jb+bX0tHY9Brw==", "vMqkqoCDG3bBEkChZEeXXw==", "K4fjSjeJbabAC/Z1ZKx4cg==", "9lvAhqt8E6OX0IDnIAoNhg==", "00/Rl+wsKmrYdMfhIsro3w==", "tlWAI5Gg3qpsattxX73mHg==", "tlWAI5Gg3qpsattxX73mHg==", "m92hNoZwzu2WZWrjQnL3pw==", "XarHw/QzUAa4WS+XlnTJ7Q==", "2FrfL9OA9L2eBerwQAT/Fw==", "9Okqe8BoKI96UOKKG9JPfA==", "5sKg58/6LBBY5odjL4GPmQ==", "2BpupYyoPVwEtWF/Smt0qQ==", "cg5GuTeeHvBtm4F/N159PA==", "bVhAx53Bo2c62RmmzM5Trg==", "lY+p5CiA7H02mhjGRW7AJA==", "O5OZQ9nS1LvOoEF645C1JA==", "p1y7dQQkT5ahFABY7J8xJw==", "knuJNibA2PBWeIAhTOzJMw==", "PTMsfmz0tOJ0QGaKbQICVA==", "qRE68/NNY43dBNJ2j8hGJg==", "TszHGyY6EyX+Ujl6Bc261Q==", "mK4h62B3fFqxWJoOZGBBAA==", "hIxUN/IVrQd5uQV48Lsi9A==", "jYcfN5R+wi8GmMhHhoJJsw==", "sgBnAtiE3ecYxmtTkldt5A==", "Fgbj7/WC6un4OHnAIfm4+A==", "7pUdSTf06n1nCU8nJNjEUQ==", "eUzgx7Bt2Qx9BCtUXgAT4A==", "KjDX/783FWspYF8xd02WQQ==", "CFbcWcKM3osLkEWwKQjQnQ==", "Smh/QW3fqp+/EJazUS3gFA==", "KwHnuKblpFV7b17OpRavSA==", "h/IXQC98hRAshKaBDIxmkQ==", "XFtLSfpZhQu906aQ8OoGLw==", "UDcoDiA7Pfa7ODnsJzhvxQ==", "pwtbEaX+Ns2sbCiUFXtkvQ==", "TqjJg7k+XzwyeFlMs8alQg==", "YvNmNVSlTL20bbp+jim8gQ==", "ra3lwcSb8Qp5fEjINxeQzQ==", "c+V/VrZ/SBProG7X0XKoZA==", "NvFH3++f+oRo8KFUrbiydQ==", "KDwEvfsbloidL08eI9qfQA==", "B7vHMuR5B89/IQqy/TA8gw==", "qwT7kAKx+2qSyPoixWTUAA==", "GuuUDAJq0lVcyjrWYoRqfw==", "3KlzvMUzo+3oL2pRDw4NYA==", "5A9CIhZsO8sKxJCfaZnRxg==", "UU6UYCDNIWDY8idgvax7oA==", "MNWaR6J2/i3qS99ru3yNmg==", "iCNQSBgXrAiw8PwVfiwB3Q==", "V3pj+rGX2CQ0yNXbjOYF3w==", "iKnbJ0vUSmKFitKFIv1xrw==", "aPbtpuZgMwHeEG3mckNZ1g==", "rPRVc++Z3RXRPd4rf3/nNw==", "7EUEm9jTzjt+5H2v74z6Uw==", "pLvATGvP0VPenCsQ0tTvbA==", "clVVpI/5KkAwVv0UDueh8Q==", "Jlme+ECl05M9mREBFkyTtQ==", "VRTj2yTuRIpkHWlCkAcf0A==", "2nl8CoSeeK5+VD7zNVbGzQ==", "Du1lQl/G5BUkyXxpHsryoQ==", "C2vs7a4B+DABG9xaEm5K1Q==", "Dr1ThUPUa02keCQ2cBWjwg==", "OXkFLO+m/ME7jbMz6RCL5Q==", "xGBE9sLue0De/ocL7VJ1Kg==", "yZlM+VC7ycqi2R51w0Po7A==", "P0KhooFqcrzHOB/1U04oVw==", "BtrGO/A6ckTrCjrcD2f2cg==", "fLRItQ6LwegPXHbr8ocSqg==", "uFHmgJXMRMV1uEs1NiWmXA==", "5oyODuwoLw7Lljnv25SorQ==", "Ey98GIFz/nMRxUekStYiKQ==", "txRYSinsplg+hgyssbCUFA==", "E5vC6x+PGP2DXlophTjZWA==", "X5CvUway7AuIe5zcQrpoXw==", "8bAOtoUtVjAo5OOn2lLzaA==", "MDnan76N2A3GMCcyFa9xCA==", "tH1bIri1pjVPVKe2PEnoOA==", "ooTWxXbh292FmVgo1kHE7A==", "a9JYIz6VKuH39DiMSWHnCg==", "Q5etfNFXpKDKHW8Y4B7kFw==", "Yv+k8HZCtnY3hW+tJIv6ZQ==", "HFNuEWAhQ/VbaKjbBjrPOw==", "XStw8oRINRtvlOxlmutdbQ==", "SlJwzLiXEiTQ18zK4mBReA==", "VimiycJJFjoEmAeHtOrpfw==", "CxSnikQmu+db862mM6a7Zg==", "jQ2MnE8McujPPnDV7zBS1g==", "nx4yfMKAWOrJGYGkv2bKwA==", "tOcV+ZJHZfCXMN9t6M0k3Q==", "VrVsZORfTkz0ys6aHlem3g==", "4V7RcHqqkb92ludTcvikEg==", "VLpd3ovnF/wU7ZZYGnWz7Q==", "5eFGExJL11SPT3sO8sYYIA==", "EVvM7X0FiVYuJMtsqNX4Vg==", "DTd5vZob/Fn8wDInbwI6BA==", "CyWDY7MHYqnZF050wUYoDg==", "p/ko+VsWk5kvy3cPG/mfSQ==", "K0MuVhdOVsmM13uwfTIEgw==", "js8VZs2pGZMIMH/i2nwZ1w==", "pHHwJ285mR4tgBzIxPW2Bg==", "aYLeaeTgdysx4K0tKzUEXA==", "YTsEWoK05hHJlFXzxOvqeQ==", "pLkvgJpAB0n/49tuJCGgbA==", "n3ILUPA3Tykn12D7p3TsHA==", "/Op9lgGKttKDNnicEbcRmg==", "kmjs1kiptFH+5gCoxPQ/MA==", "mcO2vtCww692Jg7HFNwrKA==", "rg3sD2sGtXyA3Yf9FxdPHg==", "hSMskZkL9HKjOCTWEbC+4A==", "PN3cDC7BkZKE62xa2f2fJg==", "6tIxjL0uqPP+jE3VlO8l8g==", "1CAH4jRVgVXat9A+4ic4gA==", "HZFmX3omZmvg6hl0lI2ZbA==", "AcfUyBJcyqU4BekfYl1BnQ==", "uEUdddgYekGH05Qx2Rkbkg==", "K+adLE9qMbsq59uHUDUDfg==", "9h6RuW5R13044iTkB/Xr1Q==", "QCfIifrRpZ94tzegxGwcdw==", "BlopyrD/yM6MNjb3+oiuYw==", "+j2wu9SfNikrxqDQlPYRCg==", "CEjshziCaqqyQijkvdkaXQ==", "x63qvKE3SfswMXgwATV+Ag==", "fSgnYEi9O3ekUjKJ+E9Fdw==", "ahUyepjCfGXvRlvQVndIRA==", "qSRLJH+m+YKaHgMxkwnr5Q==", "I0ph+75JEukOHsClWeLhgA==", "YAbRx0K3YUlSG5nZKBKdwg==", "QPoe4aVhcE/h1VvHL+AGRw==", "k6qk5bKz7Ntef/QfiqAfVg==", "ZR4BsKZs4MIbqInbiZlugA==", "ODucsYZc0fu6yUzNAMVVQQ==", "D+GzEp82/ILQBn4ZkDgn9A==", "CQYY7nyO/My9ONOcMUXzfA==", "daspea/oPCIvizxoEq35yQ==", "X7kQoV7/A50VqsXrNl4X4A==", "FLbJ2Rwsxkh85/OXqcBBHw==", "noBtslwRtW1EOHc8BcmIOA==", "UQehUl7I4u77zvIqw7So6Q==", "l6fir6oEtLDZ3Tdb9VxdNA==", "iYW/E66hfOOxNtggVx+TNQ==", "JDfHyVWfAFuXG6KA039SyQ==", "hFFI4hvoGNbyOi2244anHA==", "XCqtY3Q0ONOHfmsmqkNWbQ==", "AS94af2B9xtLOLjNPQGdSg==", "rZAd+Dt904lEhwQys5t5OA==", "TqbuS0bQa8DGwFr4vCSg4Q==", "vIHxmqjATTwZY1G2XWAFtQ==", "8/7tzqyjOhTxwXpuJbZY1g==", "tVxJPX50MMuzM+qgVSi/2A==", "Xnuz4zzvgYkrcEiPeu3f9w==", "YVI7pFtTuRvKNLAMjsls9A==", "MPda7frShucnlVpfqxhB0A==", "1bgu3i//+YqdQp9Zub1NPQ==", "zXdDLbSC5LeEwkedsXnKyw==", "xJcmATKFsjLsZvE7ivEX9A==", "sk8b/ihcnDaIFHbDzRSMeA==", "pe6cbAWYPw/S+/ng9f5YoA==", "30fLZPvGbHJwAOCjqTgK+w==", "92cjzuQkInakIFaSQn/fYg==", "S01NaWeUKSdZNC9QTcn/1g==", "N9j4vGkClJHhjMgj34NIXw==", "6h6VaDkRREnzIsFWkwf+hw==", "BQsUJuKizq1zjeX4D1d7CA==", "OG5L7JnUmSPoqbZes8caLw==", "Zj1qJHV+sZz10oGmCJSHJg==", "vh6m+ugpu5KYCxdzWR7Vdg==", "dGaDI0S5WFa8q8q8eCDqzw==", "sHbyTu1Mvx/9LHEuzuDD0Q==", "BzxJrED6kX+3/wZkEKJjtw==", "i34Ea4eobC2WVixTGbbJ7g==", "MtIWPeyXZiyp2MEXiP7G/Q==", "ZcuHXpWuMaKcy0AKYfG8DQ==", "6jhRvHqycKScVINt6U76Cw==", "h+YdBx/frUhtv1AWgB4Vog==", "Wf3i9bqKyCVAL2iOSZSa+w==", "E/qKjulewogrLHX+ig2h8w==", "1ss/3uF698MsjAIlrmaTVA==", "hX9ulbohcDJ8sWRzh0lCBQ==", "ZvOhUuQTtF4mkjzrwtAX7w==", "/CZ6wXih2VoMGLQu6DyOeA==", "QOMwKWvc1dOa9ojXY8q7GQ==", "KJTvqYhbzbZyyXZzr3seYA==", "zuTruC1C+ismQIULxvVz6g==", "+UUWWSr7pxCIDQ0a9TUvfQ==", "h55NeqtALtYJ6N0Ag2C8OA==", "EBOJHR5txMr2rDlDZoY4ow==", "V3TSvbo7YhSUDh+cBxokPg==", "/pPZqFbGH6nApu1eHG5QXg==", "E+flghaJm/vtjSzGf2ux3A==", "PdM+zoSwXbmGAbnOkPvptg==", "fwnnslRnRaGlBFIC+LtNvg==", "6S5cpovWr0jN0257vwPEQQ==", "HiRUlCMB1svVmKNHjDxj8g==", "JHz22YMOl1Kr3EWnlAyCag==", "js1jDkYTBSoaOUONnfVchw==", "1MnYUXz7Otnj3cOvFiEvFw==", "D7FQ4p3TGA9StKbQv8bt6w==", "wl030Qlw20lTLcwKhLkwZw==", "eOqf+/JPuzt9y4TT+jSMiQ==", "xYHUJaYraB6ZBJJtJbA9RQ==", "MW5KvNp88oJBVsBQxayYMQ==", "xsaH8j2bMpBSEKduPbBrag==", "o43+2xKm5p5vZ0COZq4NhQ==", "o56lvZgVaQ8c1YU2hizfdg==", "ipMh+6Oz71yPuH7SDDJ7ag==", "CGxHgbINV8EPdE8EtVPKsg==", "9x2kaGamnQYAhEeVjhoIsg==", "qEhFkDRVI6oBcgex7ALiyA==", "UiiZNhZB4hUGsjTumiIBjA==", "v5YL/kQmpZK0hr5g3U/rug==", "br6+AACXJHzpon7ROsHi1A==", "JcfO3/3bsyn5tVMDTjcGiw==", "Gabs20+nlTo9n7LR3CfDwA==", "96BhyVBZUqbYDX3i5PRU1g==", "+1PZbiQoZtVsCb6l3B9eMQ==", "Jot6ME+QmmI0DV2SUK+Vuw==", "gL9KwvlTqVpzkwMyf4y4gg==", "X/MkDgbbAjjlLPFYg5ISJw==", "o0m10sooeWxkXRDgZlgLbQ==", "PTcCEuBNR7oXKcGCrUmKQg==", "3oiJvr5VLEsmrbuv+Tx2CA==", "UzrI8zuotzEZ6NZuJbZ0FQ==", "e+AJ5vYvy3NtWt8buHL3Gg==", "LTCyFQ/uf+OKrukH0ZijhA==", "U+RlRD5useCemxGHy8dS6Q==", "c2pQD5+K840DqnvU5WSarg==", "zYt9MLGU5kykTkYkSAI6yQ==", "G+FfNSR3CN3DmuC35biC4Q==", "G+FfNSR3CN3DmuC35biC4Q==", "fGij4xek4eKFYff14wc84A==", "iLtxWvG46/K8fHoshkI8ww==", "IgdY+C2vfOPt27+hhncUPw==", "iFS+5K/OEZFYk9TT4AnOtg==", "EZs+9O0QIf6GItYaURXZ7g==", "p4hcUcVnQnzXRRPwxuDVYw==", "/0wbsZDk5lXg6bada1ilQg==", "5UYBd0eWYsbiZSVCZcYIqA==", "Juc5GPxrsHsb1Q3mJVTPzQ==", "E5Fk1IOgy3bEsnx6OcduCA==", "7zxyIp9vrxIILJhu9BOcYQ==", "RybjOWEPQFk6dq/xW8HwKA==", "l0d8IewZT4n/DLi3KZuJWg==", "D4lK/LiClujB3Rhnq8AwIA==", "gI2qQNVrmRR34E1j/1yheg==", "IwQ96V4bbdq2Xda7PFcIEQ==", "69TZiercZ9eibI/jGG9T6Q==", "7+Ch85TVnQknQnkmcz0VpQ==", "e2cipnzD2oiTl56+WJ6cdw==", "QyiDPs0Eev4L2zCFpBGwsA==", "M2KmiPbhqMVKnbabMdTv3A==", "s2gb6jIxWqXDxrxi2g56PQ==", "Vuhw7HgmUEYwaoJYqk1wvA==", "yvx3Mk0sFF/Bm3I5LIFh9A==", "M7TrUY2SswkL8HGyOV6idw==", "FNBXWEB7qn4AlRqFZk2dzg==", "JN/mV2lLZS/AlvH9IP6G5A==", "/PeYFDkmmmSdLRpsAPNAyw==", "wdDy01gDsNaltBgY/IXQKQ==", "LDcaasN8Amvg+f19H5ZKLQ==", "9ITYm+Uag2xsciMKfPcT9g==", "gWRrd8XQeK6RMdNgmQjsqw==", "lsnptXLJAqNSuXq/TmbKeQ==", "v4D8D/zyWKax3qweelgiWg==", "EmzprF7LQxEDIDM+lSOFlg==", "zniuAudVSzUtym6qyx//CQ==", "fmUvi8T0EUFAQmZ7uJR5QQ==", "pKge2on/nBjSFcC2eVhxvw==", "bk+CFXSN++W8qsT1AvOwCQ==", "L3lfsk7eO2baaLdvWCoD0Q==", "Y9LMBXuh948r8jjV+R2rgA==", "LR9+Xe6mYI2QCuzrblSFqQ==", "5EbqExS9rBGimRhiCs5MSw==", "jpfAPhqBRe28EbCNU+RFqw==", "H+QLptH1IkP9ygqeGGOzOw==", "DKs8w4WD2zhSVzrJ3h0sJg==", "bWZdX2lIl0CMlSZhdaBdiA==", "mUJIYStw8X5MU2PNO8ca0A==", "xUDsxOGHxtd20WsWBGUbFg==", "ybfCP2L4uJQR6Ht6sgqP+g==", "/WF0uw5cYqMxl59wNkVAQA==", "K96ZFEYROy5ppea+V9SZHg==", "OBpSV/p5qaI/8Li9EezY+A==", "sNBUYbGEKGRs57V4kFFBNw==", "xP/ULHBJ6d1j0p6ihRD7aA==", "7bjgVb6/iP7266BlNQAtVw==", "ZYkbo7fQeDmd4H7f1S//vQ==", "+zFgJZmazmpKjr1/GsA2hQ==", "XF6rfVRAw7G9viNRCYRD6w==", "e752Qt0HBcqvvS39D8yX1A==", "Rlj+vBQVZgESLrvjHMTJZw==", "IT/waejyWr435UFrYZhwZg==", "ZO670VzgbHYl0+UMPXssvQ==", "r1K+8MV+qTydshCqXvAP3w==", "+e8gWQcYjduc0weXJ65YbQ==", "ZYoG48koBeXR8DmtzQ1c5Q==", "t2mbvbOtiyaQsOwqeNM/1Q==", "leuEQF6aewS2ceuSAO6DKQ==", "Ms7pfVUYaKKinS5l4ep15A==", "KudOuAwwkaDfbHcGr/LnBQ==", "z5CyQU1sXUc6JolC7v2JZA==", "4ynbKqAda7hNN/sJ8HpPPA==", "ArCnuV/MYH71wS3M6Cs7/A==", "oyknXy4oFABlUdilnRiFMA==", "mjfh/5v2u+4bqDnbFnyWfg==", "o8lDrr0udVOllr5nRqPVsA==", "htyr59VL4l4vNxPYLj4RRg==", "VMvhsyDCBQFrWUWw0RQJJw==", "egJEP7cbTwCW9qZt+N0NsQ==", "+Cd7Rw7a5KV/Fuwtt5/jTQ==", "dHTtmkuR4OcgR0LDpV+I8A==", "5VOqh15moCi106O7A4UzPw==", "kCTfEVglv0pY0xlVMBVIeA==", "5fpMCUoKJtr9s6TBKlKG5g==", "Ly05nw6ohEhZ/lUUswRzOw==", "5Ahg6YHstYfhDOxNPSMlwA==" };

        public static Dictionary<String, String> MachineEnum()
        {
            var commandString = Environment.CommandLine.Split();
            //	var localZone = TimeZoneInfo.Local;
            var results = new Dictionary<String, String>
            {
                { "Computer Name", Environment.MachineName },
                { "Domain", Environment.UserDomainName },
                { "CPU Count", Environment.ProcessorCount.ToString() },
                { "OS Version", Environment.OSVersion.ToString() },
                { "Platform", Environment.OSVersion.Platform.ToString() },
                { "Service Pack", Environment.OSVersion.ServicePack },
                { ".NET Version", Environment.Version.ToString() },
                { ".NET Installed", ClrVer.GetVersionFromRegistry()},
                { "Architecture OS", (is64BitOperatingSystem) ? "64bit" : "32Bit" },
                { $"Architecture PID {Process.GetCurrentProcess().Id} ", (is64BitProcess) ? "64bit" : "32Bit" },
                { $"PID", Process.GetCurrentProcess().Id.ToString()},
                { "Date/Time", DateTime.Now.ToString()},
			//	{ $"Time Zone ID", localZone.Id.ToString()},
				//{ $"Time Zone", localZone.DisplayName.ToString()},
				{ $"System Boot Time", DateTime.Now.AddMilliseconds(-Environment.TickCount).ToString()}
            };

            foreach (var ni in GetAllNetworkInterfaces())
                if (ni.NetworkInterfaceType == Wireless80211 || ni.NetworkInterfaceType == Ethernet)
                    foreach (var ip in ni.GetIPProperties().UnicastAddresses) if (ip.Address.AddressFamily == InterNetwork)
                            results.Add($"Network Interface {ni.Name}", $"{ni.Description} -  - {ip.Address.ToString()}");
            return results;
        }
        public static Dictionary<String, String> UserEnum()
        {
            var principal = new WindowsPrincipal(GetCurrent());
            var mapGroupsToUsers = new Dictionary<String, List<String>>
            {
                { "administrators", GetUsersForGroup("administrators") },
                { "remote desktop users", GetUsersForGroup("remote desktop users") }
            };

            var results = new Dictionary<String, String>
            {
                { "Domain", Environment.UserDomainName},
                { "Username", Environment.UserName},
                { "UserInteractive", Environment.UserInteractive.ToString()},
                { "Is User Elevated", principal.IsInRole(Administrator).ToString()}
            };

            var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (null != key)
                results.Add("Proxy", key.GetValue("ProxyServer").ToString());

            var uacKeys = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            if (null != uacKeys)
            {
                var badmin = (uacKeys.GetValue("ConsentPromptBehaviorAdmin")) as Int32?;
                if (badmin.HasValue && _badmin.ContainsKey(badmin.Value))
                    results.Add("Admin UAC", _badmin[badmin.Value]);
                else
                    results.Add("Admin UAC", "UNABLE TO RESOLVE");

                var uadmin = (uacKeys.GetValue("ConsentPromptBehaviorUser")) as Int32?;
                if (uadmin.HasValue && _uadmin.ContainsKey(uadmin.Value))
                    results.Add("User UAC", _uadmin[uadmin.Value]);
                else
                    results.Add("User UAC", "UNABLE TO RESOLVE");

                var lua = (uacKeys.GetValue("EnableLUA")) as Int32?;
                if (lua.HasValue && _uaclua.ContainsKey(lua.Value))
                    results.Add("UAC Lua", _uaclua[lua.Value]);
                else
                    results.Add("UAC Lua", "UNABLE TO RESOLVE");
                key.Close();
            }
            return results;
        }
        public static List<String> RecentFiles(Int32 number = 10)
        {
            var files = new List<String>();
            var recent = $@"C:\Users\{Environment.UserName}\AppData\Roaming\Microsoft\Windows\Recent";
            var sortedFiles = new List<FileInfo>();
            sortedFiles.AddRange(new DirectoryInfo(recent).GetFiles());
            sortedFiles.Sort((f1, f2) => { return File.GetLastWriteTime(f2.FullName).CompareTo(File.GetLastWriteTime(f1.FullName)); });
            var ctr = 0;
            foreach (var n in sortedFiles)
            {
                files.Add(n.FullName);
                if (++ctr >= 10)
                    break;
            }
            return files;
        }
        public static List<String> EnumProcesses()
        {
            var procs = new List<String>();
            using (var md5 = System.Security.Cryptography.MD5.Create())
            {
                foreach (var proc in Process.GetProcesses())
                    if (_avlist.Contains(ToBase64String(md5.ComputeHash(ASCII.GetBytes(proc.ProcessName)))))
                        procs.Add($"{proc.ProcessName} PID: {proc.Id}");
            }
            return procs;
        }
        public static List<String> ChrBookmarks()
        {
            var results = new List<String>();
            var bookmarksFile = $@"C:\Users\{Environment.UserName}\AppData\Local\Google\Chrome\User Data\Default\bookmarks";
            string name = null;
            foreach (var line in File.ReadAllLines(bookmarksFile))
            {
                var ln = line.Trim();
                if (ln.StartsWith("\"name\": \""))
                    name = ln.Substring(8).Replace("\"", "");
                else if (ln.StartsWith("\"url\": \""))
                    results.Add(name + ":" + ln.Substring(7).Replace("\"", ""));
            }
            return results;
        }
        public static List<String> IEBookmarks()
        {
            var results = new List<String>();
            var allFiles = Directory.GetFiles($@"c:\Users\{Environment.UserName}\Favorites\", "*.url", SearchOption.AllDirectories);
            foreach (string file in allFiles)
                foreach (var ln in File.ReadAllLines(file))
                    if (ln.Trim().StartsWith("URL"))
                        results.Add($"{System.IO.Path.GetFileName(file)}:{ln.Substring(4)}");
            return results;
        }
        public static List<String> InstSoftware()
        {
            var results = new List<String>();
            var names = new SortedDictionary<String, String>();
            using (var rk = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
            {
                foreach (var skName in rk?.GetSubKeyNames())
                {
                    using (var sk = rk?.OpenSubKey(skName))
                    {
                        try
                        {
                            var displayName = sk?.GetValue("DisplayName") as String;
                            var displayVersion = sk?.GetValue("DisplayVersion") as String;
                            if (!String.IsNullOrEmpty(displayName) && !String.IsNullOrEmpty(displayVersion))
                                if (!names.ContainsKey(displayName))
                                    names.Add(displayName, displayVersion);
                        }
                        catch { }
                    }
                }
            }
            foreach (var kv in names)
                results.Add($"{kv.Key} - Version: {names[kv.Key]}");
            return results;
        }
        public static List<string> GetUsersForGroup(String groupName)
        {
            var lstUsers = new List<String>();
            var localMachine = new DirectoryEntry("WinNT://" + Environment.MachineName);
            if (localMachine?.Children?.Find(groupName, "group")?.Invoke("members", null) is IEnumerable rdpMembers)
                foreach (var groupMember in rdpMembers)
                    lstUsers.Add((new DirectoryEntry(groupMember))?.Name);

            return lstUsers;
        }

        //https://stackoverflow.com/questions/336633/how-to-detect-windows-64-bit-platform-with-net
        static bool is64BitProcess = (IntPtr.Size == 8);
        static bool is64BitOperatingSystem = is64BitProcess || InternalCheckIsWow64();

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(
            [In] IntPtr hProcess,
            [Out] out bool wow64Process
        );

        public static bool InternalCheckIsWow64()
        {
            if ((Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor >= 1) ||
                Environment.OSVersion.Version.Major >= 6)
            {
                using (Process p = Process.GetCurrentProcess())
                {
                    if (!IsWow64Process(p.Handle, out bool retVal))
                        return false;
                    return retVal;
                }
            }
            else
                return false;
        }
    }
}
