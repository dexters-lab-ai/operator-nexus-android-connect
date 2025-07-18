// Connect to MongoDB Atlas via Mongoose
const mongoose = require('mongoose');
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// Define User schema and model
const historySchema = new mongoose.Schema({
  command: String,
  result: mongoose.Schema.Types.Mixed,
  timestamp: Date
}, { _id: true });  // each history entry gets its own _id

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, default: '' },
  lastName: { type: String, default: '' },
  displayName: { type: String },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now },
  apiKeys: {
    openai: { type: String },
    anthropic: { type: String },
    midscene: { type: String },
    google: { type: String }
  },
  preferences: {
    defaultEngine: { type: String, default: 'gpt-4' },
    theme: { type: String, default: 'dark' },
    accessibility: {
      reduceMotion: { type: Boolean, default: false },
      highContrast: { type: Boolean, default: false },
      largeText: { type: Boolean, default: false }
    },
    privacy: {
      saveHistory: { type: Boolean, default: true },
      analytics: { type: Boolean, default: false }
    },
    interface: {
      compactMode: { type: Boolean, default: false },
      showHelp: { type: Boolean, default: true }
    }
  },
  llmPreferences: {
    default: { type: String, default: 'gpt-4' },
    code: { type: String, default: 'default' },
    content: { type: String, default: 'default' },
    research: { type: String, default: 'default' }
  },
  status: { type: String, default: 'active' },
  history: [ historySchema ]     // array of task history entries
});
const User = mongoose.model('User', userSchema);
