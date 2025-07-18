module.exports = {
    apps: [
      {
        name: "operator-server",
        script: "./server.js",
        instances: "max",
        exec_mode: "cluster",
        env: {
          NODE_ENV: "production",
          PORT: 3400,
        },
        autorestart: true,
        watch: false,
        max_memory_restart: "1G",
        log_date_format: "YYYY-MM-DD HH:mm:ss",
        error_file: "./logs/err.log",
        out_file: "./logs/out.log",
        time: true,
      },
    ],
  };