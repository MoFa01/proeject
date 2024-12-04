const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URL = "mongodb+srv://GP:gp12345@cluster0.a4hua.mongodb.net/";
const JWT_SECRET = 'key'; // Replace with a secure secret key


const cors = require('cors');
app.use(cors());
// Middleware
app.use(express.json());

// MongoDB Connection
mongoose.connect(MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully'))
.catch((err) => console.log('MongoDB connection error:', err));

// User Schema (covers students, instructors, administrators)
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { 
    type: String, 
    enum: ['student', 'instructor', 'admin'], 
    required: true 
  }
});

// Course Schema
const CourseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  instructor: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  materials: [{
    type: { type: String, enum: ['lecture', 'reading', 'multimedia'] },
    content: { type: String, required: true }
  }],
  assignments: [{
    title: String,
    description: String,
    dueDate: Date,
    maxScore: Number
  }]
});

// Enrollment Schema
const EnrollmentSchema = new mongoose.Schema({
  student: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    required: true
  },
  course: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Course',
    required: true
  },
  progress: { type: Number, default: 0 },
  grades: [{
    assignmentId: mongoose.Schema.Types.ObjectId,
    score: Number,
    feedback: String
  }],
  status: { 
    type: String, 
    enum: ['active', 'completed', 'dropped'], 
    default: 'active' 
  }
});

// Models
const User = mongoose.model('User', UserSchema);
const Course = mongoose.model('Course', CourseSchema);
const Enrollment = mongoose.model('Enrollment', EnrollmentSchema);

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// Middleware for authentication
const authenticateUser = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ _id: decoded.userId });

    if (!user) {
      throw new Error();
    }

    req.token = token;
    req.user = user;
    next();
  } catch (error) {
    res.status(401).send({ error: 'Please authenticate.' });
  }
};

// Authorization middleware
const authorize = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).send({ error: 'Access denied' });
    }
    next();
  };
};


async function deleteAllDocuments() {
  try {
    await User.deleteMany({});
    await Course.deleteMany({});
    await Enrollment.deleteMany({});
    console.log('All documents in User, Course, and Enrollment collections have been deleted.');
  } catch (error) {
    console.error('Error deleting documents:', error);
  }
}

// Endpoint to trigger document deletion
app.delete('/delete-documents', async (req, res) => {
  await deleteAllDocuments();
  res.send('All documents have been deleted from User, Course, and Enrollment collections.');
});

app.post('/register', async (req, res) => {
  try {
    const { username, email, password, role, firstName, lastName } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    if (existingUser) {
      return res.status(400).send({ error: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      role
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: '10000h' }
    );

    res.status(201).send({ user, token });
  } catch (error) {
    res.status(400).send(error);
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).send({ error: 'Login failed' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send({ error: 'Login failed' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: '10000h' }
    );

    res.send({ user, token });
  } catch (error) {
    res.status(400).send(error);
  }
});

// Course Creation (for Instructors)
app.post('/courses', authenticateUser, authorize(['instructor']), async (req, res) => {
  try {
    const { title, description, materials, assignments } = req.body;

    const course = new Course({
      title,
      description,
      instructor: req.user._id,
      materials,
      assignments
    });

    await course.save();
    res.status(201).send(course);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Get Courses (for Students)
app.get('/courses', authenticateUser, async (req, res) => {
  try {
    let courses;
    if (req.user.role === 'student') {
      // For students, fetch all courses or enrolled courses
      const enrollments = await Enrollment.find({ 
        student: req.user._id 
      }).populate('course');
      courses = enrollments.map(enrollment => enrollment.course);
    } else if (req.user.role === 'instructor') {
      // For instructors, fetch their own courses
      courses = await Course.find({ instructor: req.user._id });
    } else {
      // For admins, fetch all courses
      courses = await Course.find();
    }

    res.send(courses);
  } catch (error) {
    res.status(500).send(error);
  }
});

// Enroll in Course (for Students)
app.post('/courses/:courseId/enroll', 
  authenticateUser, 
  authorize(['student']), 
  async (req, res) => {
    try {
      const courseId = req.params.courseId;
      
      // Check if course exists
      const course = await Course.findById(courseId);
      if (!course) {
        return res.status(404).send({ error: 'Course not found' });
      }

      // Check if already enrolled
      const existingEnrollment = await Enrollment.findOne({
        student: req.user._id,
        course: courseId
      });

      if (existingEnrollment) {
        return res.status(400).send({ error: 'Already enrolled in this course' });
      }

      // Create enrollment
      const enrollment = new Enrollment({
        student: req.user._id,
        course: courseId
      });

      await enrollment.save();
      res.status(201).send(enrollment);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Submit Assignment (for Students)
app.post('/courses/:courseId/assignments/:assignmentId/submit', 
  authenticateUser, 
  authorize(['student']), 
  upload.single('submission'),
  async (req, res) => {
    try {
      const { courseId, assignmentId } = req.params;
      const submissionFile = req.file;

      // Validate enrollment
      const enrollment = await Enrollment.findOne({
        student: req.user._id,
        course: courseId
      });

      if (!enrollment) {
        return res.status(403).send({ error: 'Not enrolled in this course' });
      }

      // Update enrollment with assignment submission
      enrollment.grades.push({
        assignmentId,
        score: null,
        feedback: null
      });

      await enrollment.save();

      res.status(201).send({
        message: 'Assignment submitted',
        file: submissionFile.filename
      });
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// Grade Assignment (for Instructors)
app.post('/courses/:courseId/assignments/:assignmentId/grade', 
  authenticateUser, 
  authorize(['instructor']), 
  async (req, res) => {
    try {
      const { courseId, assignmentId } = req.params;
      const { studentId, score, feedback } = req.body;

      // Verify course belongs to instructor
      const course = await Course.findOne({
        _id: courseId,
        instructor: req.user._id
      });

      if (!course) {
        return res.status(403).send({ error: 'Not authorized to grade this course' });
      }

      // Update student's enrollment
      const enrollment = await Enrollment.findOne({
        student: studentId,
        course: courseId
      });

      if (!enrollment) {
        return res.status(404).send({ error: 'Enrollment not found' });
      }

      // Find and update the specific assignment grade
      const gradeIndex = enrollment.grades.findIndex(
        grade => grade.assignmentId.toString() === assignmentId
      );

      if (gradeIndex !== -1) {
        enrollment.grades[gradeIndex].score = score;
        enrollment.grades[gradeIndex].feedback = feedback;
      } else {
        enrollment.grades.push({
          assignmentId,
          score,
          feedback
        });
      }

      await enrollment.save();
      res.send(enrollment);
    } catch (error) {
      res.status(400).send(error);
    }
  }
);

// User Management (for Administrators)
app.get('/admin/users', 
  authenticateUser, 
  authorize(['admin']), 
  async (req, res) => {
    try {
      const users = await User.find({}, { password: 0 });
      res.send(users);
    } catch (error) {
      res.status(500).send(error);
    }
  }
);

// Delete User (for Administrators)
app.delete('/admin/users/:userId', 
  authenticateUser, 
  authorize(['admin']), 
  async (req, res) => {
    try {
      const user = await User.findByIdAndDelete(req.params.userId);
      
      if (!user) {
        return res.status(404).send({ error: 'User not found' });
      }

      res.send({ message: 'User deleted successfully' });
    } catch (error) {
      res.status(500).send(error);
    }
  }
);

//================================================================
//================================================================
app.get('/AllcoursesEn',authenticateUser,authorize(['student']) ,async (req, res) => {
  try {
    // Assuming the student ID is passed as a token or part of the session
    const studentId = req.user._id; // Replace with actual student ID retrieval logic

    // Fetch all courses
    const courses = await Course.find();

    // Fetch enrollments for the student
    const enrollments = await Enrollment.find({ student: studentId }).populate('course');

    // Map enrollments to get course IDs the student is enrolled in
    const enrolledCourseIds = enrollments.map(enrollment => enrollment.course._id.toString());

    // Add enrollment status to each course
    const coursesWithEnrollmentStatus = courses.map(course => {
      return {
        ...course.toObject(),
        enrolled: enrolledCourseIds.includes(course._id.toString())
      };
    });

    // Send the response with the courses and enrollment status
    res.status(200).json(coursesWithEnrollmentStatus);
  } catch (error) {
    console.error('Error fetching courses:', error);
    res.status(500).json({ message: 'An error occurred while fetching courses.' });
  }
});

app.get('/courses/:courseId/details', authenticateUser,authorize(['student']),async (req, res) => {
  try {
    const courseId = req.params.courseId;
    const studentId = req.user._id; // Replace with actual student ID retrieval logic

    // Fetch the course
    const course = await Course.findById(courseId);

    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // Fetch the student's enrollment in the course
    const enrollment = await Enrollment.findOne({
      student: studentId,
      course: courseId
    });

    if (!enrollment) {
      return res.status(403).json({ message: 'You are not enrolled in this course' });
    }

    // Mark assignments as "done" if the student has submitted them
    const assignmentsWithStatus = course.assignments.map(assignment => {
      const isDone = enrollment.grades.some(grade =>
        grade.assignmentId.toString() === assignment._id.toString()
      );
      return {
        ...assignment.toObject(),
        done: isDone
      };
    });

    // Send the response with materials and assignments
    res.status(200).json({
      materials: course.materials,
      assignments: assignmentsWithStatus
    });
  } catch (error) {
    console.error('Error fetching course details:', error);
    res.status(500).json({ message: 'An error occurred while fetching course details.' });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;