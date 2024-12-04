const express = require('express');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URL = "mongodb+srv://GP:gp12345@cluster0.a4hua.mongodb.net/your_database_name"; // Replace with your database name

// MongoDB connection
mongoose.connect(MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected successfully'))
  .catch((err) => console.log('MongoDB connection error:', err));

// Function to delete all data
async function deleteAllData() {
  try {
    const db = mongoose.connection.db; // Get the database instance
    await db.dropDatabase(); // Drop the entire database
    console.log('Database has been deleted successfully.');
  } catch (error) {
    console.error('Error deleting database:', error);
  }
}

// Endpoint to delete all data
app.delete('/delete-all-data', async (req, res) => {
  await deleteAllData();
  res.send('All data has been deleted.');
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
