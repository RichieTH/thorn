// thorn test fixture: SEC003, SEC004

const config = {
  // SEC003: generic API key pattern
  apiKey: "sk-abc123def456ghi789jkl012mno345pqr678stu",

  // SEC004: hardcoded password
  dbPassword: "password=SuperSecret123!",
  adminPass: "admin_password = 'hunter2'",

  // should NOT match
  apiEndpoint: "https://api.example.com/v1",
  timeout: 3000,
};

module.exports = config;
