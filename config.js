module.exports = {
    serverConfig:{
        port:80,
        public_key:"-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4HGY/1ErFSvTHU7ik15dlCqRuHfskshkbvgKtwr/prpWSZgfVtaiQL0U3gnuojApst5/joxFK9RTRnWd6C1k9izGwQ5dHgECCUqBWmLrwNiCh/13AQ+X3ZT5MiMqtbTvTirBeeFrhEM6RJtfHcQefFsAc3EFh4DwNSyCWwp4xrwIDAQAB-----END PUBLIC KEY-----",
        private_key:"-----BEGIN PRIVATE KEY-----MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALgcZj/USsVK9MdTuKTXl2UKpG4d+ySyGRu+Aq3Cv+mulZJmB9W1qJAvRTeCe6iMCmy3n+OjEUr1FNGdZ3oLWT2LMbBDl0eAQIJSoFaYuvA2IKH/XcBD5fdlPkyIyq1tO9OKsF54WuEQzpEm18dxB58WwBzcQWHgPA1LIJbCnjGvAgMBAAECgYB76rFvWKWSsOabml/2oxzE5yrQ6uD0S+LWZ0dKSH/++oC1bnLrhj8T/JzrxakRQmBp2BWHk2O6PcZrZzQUUrsWqhWqkDBGg4BD9wxhd/MPrNn+rNZ6WjqrZ3RPJRv+nvVjophczpsJut/Ld0Gb2lZvb5vTQoO74HsR8zMgzi2ZYQJBAOpZjeI6ZqFOBL3C7vh5VpXChrxMdiAYKlWZ0NX726x8a7DFtWIB3E538ioVO28QG9GYP20Bk3wCsCkNuT1FnnkCQQDJHq4TWFAJJaK3pmr0lJ42O2FLvj5mli5Fm1JPX2zbOVZe4/F9AQV3uqazO5ftwby848hpZLQlY1VdwJ2abydnAkEAxTNOvYu/SQVJ4BTk2pngTm0+y7zbue4b0aR5o1coZ2DbjgkQtMQ0CqPMV7U+Khs4DYs79BJbdQMeEa3GrtSioQJAFVi4ST1aYV4pQyzatVMA5+itjwiGPwU5rBGsTthmCW6wiCnRe98b4XViNCvjGE0z5yiWIPmbVUyRxv2mvLmHiQJAO3w/lN9gWiKZi5S2NC0SNCPMArmPd/jqmCNzloiKv2+JjmdnLZVos8E46gz1xi0NhKxeNcsBbJDgCrY2WUJPnA==-----END PRIVATE KEY-----",
        salt:"?Gu7*K5-FtbUKFe:d}+Y",
        jwt_expires:"24h",
    },
    fileConfig:{
        //directory不能等于tempdirectory
        //tempdirectory不能为directory的子目录
        directory:"G:\\upload",
        tempdirectory:"G:\\",
        allow_override:false
    },
    user_db:{
        allow_guest_login:true,
        guest_privilege:["list", "download"],
        "root": {
            "password": "$2a$10$6K.9cIurlACRkHp2jLFay.nVuMLlT.PC8ip7Dm6T4znNYJ0GD1956",
            "privilege": ["list", "download", "delete", "upload"]
        }
    },
};
