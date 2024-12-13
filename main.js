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
  },
  isApproved: {
    type: Boolean,
    default: false // Default value set to false
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
    cb(null, file.originalname);
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




app.post('/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    if (existingUser) {
      return res.status(400).send({ error: 'User already exists' });
    }
    if(role === 'admin') {
      return res.status(400).send({ error: 'Admin role is not allowed for registration' });
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

    res.status(201).send({ user});
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
    if(user.isApproved === false){
      return res.status(401).send({ error: 'Login failed: because the admin has not approved you yet' });
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


// Enroll in Course (for Students)
app.post('/courses/:courseId/enroll/:studentId', 
  authenticateUser, 
  authorize(['admin']), 
  async (req, res) => {
    try {
      const courseId = req.params.courseId;
      const studentId = req.params.studentId;
      
      // Check if course exists
      const course = await Course.findById(courseId);
      if (!course) {
        return res.status(404).send({ error: 'Course not found' });
      }

      // Check if already enrolled
      const existingEnrollment = await Enrollment.findOne({
        student: studentId,
        course: courseId
      });

      if (existingEnrollment) {
        return res.status(400).send({ error: 'Already enrolled in this course' });
      }

      // Create enrollment
      const enrollment = new Enrollment({
        student: studentId,
        course: courseId
      });

      await enrollment.save();
      res.status(201).send(enrollment);
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

app.get('/courses/:courseId/details',
  authenticateUser,
  authorize(['student']),
  async (req, res) => {
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

      // Map through the assignments and include grade details if available
      const assignmentsWithGrades = course.assignments.map(assignment => {
        const grade = enrollment.grades.find(
          g => g.assignmentId.toString() === assignment._id.toString()
        );

        return {
          ...assignment.toObject(),
          score: grade ? grade.score : null,
          feedback: grade ? grade.feedback : null
        };
      });

      // Send the response with materials and assignments
      res.status(200).json({
        materials: course.materials,
        assignments: assignmentsWithGrades
      });
    } catch (error) {
      console.error('Error fetching course details:', error);
      res.status(500).json({ message: 'An error occurred while fetching course details.' });
    }
  }
);

//---------
const AssignmentSubmissionSchema = new mongoose.Schema({
  assignment: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  student: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  submissionFile: {
    type: String,
    required: true
  },
  submissionDate: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    enum: ['submitted', 'graded'],
    default: 'submitted'
  }
});

const AssignmentSubmission = mongoose.model('AssignmentSubmission', AssignmentSubmissionSchema);

app.post('/assignments/:assignmentId/submit',authenticateUser,authorize(['student']),  upload.single('file'), async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const studentId = req.user._id; // Replace with actual authentication logic

    // Check if the assignment exists in a course
    const course = await Course.findOne({ 'assignments._id': assignmentId });

    if (!course) {
      return res.status(404).json({ message: 'Assignment not found' });
    }

    // Ensure the student is enrolled in the course
    const enrollment = await Enrollment.findOne({
      student: studentId,
      course: course._id
    });

    if (!enrollment) {
      return res.status(403).json({ message: 'You are not enrolled in this course' });
    }

    // Check if the student has already submitted the assignment
    const existingSubmission = await AssignmentSubmission.findOne({
      assignment: assignmentId,
      student: studentId
    });

    if (existingSubmission) {
      return res.status(400).json({ message: 'Assignment already submitted.' });
    }

    const submissionFile1 = req.file;
    console.log(req.file);
    const tempFileName ="file:///" + __dirname + "/" + "uploads/" + submissionFile1.filename;

    // Save the submission
    const newSubmission = new AssignmentSubmission({
      assignment: assignmentId,
      student: studentId,
      submissionFile: tempFileName // Path to the uploaded file
    });

    await newSubmission.save();

    res.status(200).json({ message: 'Assignment submitted successfully!', submission: newSubmission });
  } catch (error) {
    console.error('Error submitting assignment:', error);
    res.status(500).json({ message: 'An error occurred while submitting the assignment.' });
  }
});
app.get('/courses/:courseId/assignments', authenticateUser, 
  authorize(['instructor']), async (req, res) => {
  try {
    const { courseId } = req.params;
    const instructorId = req.user._id; // Replace with actual authentication logic

    // Check if the course exists and is created by the instructor
    const course = await Course.findOne({ _id: courseId, instructor: instructorId });

    if (!course) {
      return res.status(403).json({ message: 'You do not have permission to access this course.' });
    }

    // Fetch all assignments and their submissions
    const submissions = await AssignmentSubmission.find({
      assignment: { $in: course.assignments.map(a => a._id) }
    }).populate('student', 'username email');

    res.status(200).json({
      course: {
        title: course.title,
        assignments: course.assignments.map(assignment => ({
          ...assignment.toObject(),
          submissions: submissions.filter(sub => sub.assignment.toString() === assignment._id.toString())
        }))
      }
    });
  } catch (error) {
    console.error('Error fetching assignments:', error);
    res.status(500).json({ message: 'An error occurred while fetching assignments.' });
  }
});



app.put('/assignments/:assignmentId/submissions/:submissionId/grade',authenticateUser, 
  authorize(['instructor']),  async (req, res) => {
    try {
      const { assignmentId, submissionId } = req.params;
      const { score, feedback } = req.body;
      const instructorId = req.user._id; // Replace with actual authentication logic
  
      // Validate that the course and assignment belong to the instructor
      const course = await Course.findOne({ 'assignments._id': assignmentId, instructor: instructorId });
  
      if (!course) {
        return res.status(403).json({ message: 'You do not have permission to grade this assignment.' });
      }
  
      // Validate the submission exists
      const submission = await AssignmentSubmission.findOne({
        _id: submissionId,
        assignment: assignmentId
      });
  
      if (!submission) {
        return res.status(404).json({ message: 'Submission not found.' });
      }
  
      // Update the submission with score, feedback, and status
      submission.status = 'graded';
      await submission.save();
  
      // Update the student's grade in their Enrollment
      const enrollment = await Enrollment.findOne({
        student: submission.student,
        course: course._id
      });
  
      if (!enrollment) {
        return res.status(404).json({ message: 'Enrollment not found for this student.' });
      }
  
      // Update or add the assignment grade
      const gradeIndex = enrollment.grades.findIndex(grade =>
        grade.assignmentId.toString() === assignmentId
      );
  
      if (gradeIndex > -1) {
        // Update existing grade
        enrollment.grades[gradeIndex].score = score;
        enrollment.grades[gradeIndex].feedback = feedback;
      } else {
        // Add new grade
        enrollment.grades.push({
          assignmentId,
          score,
          feedback
        });
      }
  
      await enrollment.save();
  
      res.status(200).json({
        message: 'Submission graded successfully.',
        submission,
        enrollment
      });
    } catch (error) {
      console.error('Error grading submission:', error);
      res.status(500).json({ message: 'An error occurred while grading the submission.' });
    }
});

app.get('/courses/:courseId/grades',
  authenticateUser,
  authorize(['instructor']),
  async (req, res) => {
    try {
      const { courseId } = req.params;
      const instructorId = req.user._id; // Replace with actual instructor ID retrieval logic

      // Ensure the instructor owns the course
      const course = await Course.findOne({ _id: courseId, instructor: instructorId });

      if (!course) {
        return res.status(403).json({ message: 'You do not have permission to view grades for this course.' });
      }

      // Fetch all enrollments for the course
      const enrollments = await Enrollment.find({ course: courseId }).populate('student', 'username email');

      // Format grades for response
      const gradesReport = enrollments.map(enrollment => ({
        student: {
          id: enrollment.student._id,
          username: enrollment.student.username,
          email: enrollment.student.email
        },
        grades: enrollment.grades.map(grade => ({
          assignmentId: grade.assignmentId,
          score: grade.score,
          feedback: grade.feedback
        })),
        status: enrollment.status
      }));

      res.status(200).json({
        course: {
          id: course._id,
          title: course.title
        },
        grades: gradesReport
      });
    } catch (error) {
      console.error('Error fetching grades:', error);
      res.status(500).json({ message: 'An error occurred while fetching grades.' });
    }
  }
);

app.get('/courses/:courseId/my-grades',
  authenticateUser,
  authorize(['student']),
  async (req, res) => {
    try {
      const { courseId } = req.params;
      const studentId = req.user._id; // Replace with actual student ID retrieval logic

      // Verify if the course exists
      const course = await Course.findById(courseId);

      if (!course) {
        return res.status(404).json({ message: 'Course not found.' });
      }

      // Fetch the student's enrollment for the course
      const enrollment = await Enrollment.findOne({
        student: studentId,
        course: courseId
      });

      if (!enrollment) {
        return res.status(403).json({ message: 'You are not enrolled in this course.' });
      }

      // Return the grades for the enrolled course
      res.status(200).json({
        course: {
          id: course._id,
          title: course.title
        },
        grades: enrollment.grades.map(grade => ({
          assignmentId: grade.assignmentId,
          score: grade.score,
          feedback: grade.feedback
        }))
      });
    } catch (error) {
      console.error('Error fetching grades:', error);
      res.status(500).json({ message: 'An error occurred while fetching grades.' });
    }
  }
);


app.get('/my-grades',
  authenticateUser,
  authorize(['student']),
  async (req, res) => {
    try {
      const studentId = req.user._id; // Replace with actual student ID retrieval logic

      // Fetch all enrollments for the student
      const enrollments = await Enrollment.find({ student: studentId }).populate('course', 'title');

      // Filter and map grades for each course
      const coursesWithGrades = await Promise.all(
        enrollments
          .filter(enrollment => enrollment.grades && enrollment.grades.length > 0)
          .map(async enrollment => {
            // Fetch assignment details for grades
            const gradesWithAssignmentNames = await Promise.all(
              enrollment.grades.map(async grade => {
                const assignment = await Course.findOne(
                  { 'assignments._id': grade.assignmentId },
                  { 'assignments.$': 1 } // Get only the matched assignment
                );

                const assignmentName = assignment?.assignments[0]?.title || 'Unknown Assignment';

                return {
                  assignmentId: grade.assignmentId,
                  assignmentName,
                  score: grade.score,
                  feedback: grade.feedback
                };
              })
            );

            return {
              course: {
                id: enrollment.course._id,
                title: enrollment.course.title
              },
              grades: gradesWithAssignmentNames
            };
          })
      );

      if (coursesWithGrades.length === 0) {
        return res.status(200).json({ message: 'No grades found for any courses.' });
      }

      res.status(200).json({ courses: coursesWithGrades });
    } catch (error) {
      console.error('Error fetching grades:', error);
      res.status(500).json({ message: 'An error occurred while fetching grades.' });
    }
  }
);


app.get('/my-assignments',
  authenticateUser,
  authorize(['student']),
  async (req, res) => {
    try {
      const studentId = req.user._id; // Replace with actual student ID retrieval logic

      // Fetch all enrollments for the student
      const enrollments = await Enrollment.find({ student: studentId }).populate('course', 'title assignments');

      // Extract assignments from enrolled courses
      const assignments = enrollments.flatMap(enrollment => {
        return enrollment.course.assignments.map(assignment => ({
          assignmentId: assignment._id,
          assignmentName: assignment.title
        }));
      });

      if (assignments.length === 0) {
        return res.status(200).json({ message: 'No assignments found for enrolled courses.' });
      }

      res.status(200).json({ assignments });
    } catch (error) {
      console.error('Error fetching assignments:', error);
      res.status(500).json({ message: 'An error occurred while fetching assignments.' });
    }
  }
);

app.get('/instructor/my-courses/students-grades',
  authenticateUser,
  authorize(['instructor']),
  async (req, res) => {
    try {
      const instructorId = req.user._id;

      // Fetch all courses created by the instructor
      const courses = await Course.find({ instructor: instructorId });

      const result = [];

      for (const course of courses) {
        // Fetch enrollments for the current course
        const enrollments = await Enrollment.find({ course: course._id }).populate('student', 'username');

        if (enrollments.length === 0) {
          // Skip courses with no enrolled students
          continue;
        }

        // Build the response
        for (const enrollment of enrollments) {
          for (const assignment of course.assignments) {
            const grade = enrollment.grades.find(g => g.assignmentId.toString() === assignment._id.toString());
            result.push({
              courseName: course.title,
              studentName: enrollment.student.username,
              assignmentName: assignment.title,
              score: grade ? grade.score : 0
            });
          }
        }
      }

      if (result.length === 0) {
        return res.status(404).json({ message: 'No grades found for any courses with students.' });
      }

      res.status(200).json(result);
    } catch (error) {
      console.error('Error fetching grades:', error);
      res.status(500).json({ message: 'An error occurred while fetching grades.' });
    }
  }
);



app.get('/admin/unapproved-users',
  authenticateUser,
  authorize(['admin']), // Ensure only admin can access
  async (req, res) => {
    try {
      // Fetch all users where isApproved is false
      const unapprovedUsers = await User.find({ isApproved: false }).select(
        'username email role'
      );

      if (unapprovedUsers.length === 0) {
        return res.status(200).json({ message: 'No unapproved users found.' });
      }

      res.status(200).json({
        message: 'Unapproved users retrieved successfully.',
        users: unapprovedUsers
      });
    } catch (error) {
      console.error('Error fetching unapproved users:', error);
      res.status(500).json({ message: 'An error occurred while fetching unapproved users.' });
    }
  }
);

app.patch('/admin/approve-user/:userId',
  authenticateUser,
  authorize(['admin']), // Ensure only admin can access
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Find the user by ID
      const user = await User.findById(userId);

      if (!user) {
        return res.status(404).json({ message: 'User not found.' });
      }

      if (user.isApproved) {
        return res.status(400).json({ message: 'User is already approved.' });
      }

      // Update the user's isApproved field to true
      user.isApproved = true;
      await user.save();

      res.status(200).json({
        message: 'User approved successfully.',
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
          isApproved: user.isApproved
        }
      });
    } catch (error) {
      console.error('Error approving user:', error);
      res.status(500).json({ message: 'An error occurred while approving the user.' });
    }
  }
);

app.get('/admin/add-admin', async (req, res) => {
  const salt = await bcrypt.genSalt(10);
  const password1 = 'admin'; // Replace with desired password
  const hashedPassword = await bcrypt.hash(password1, salt);
  const role = 'admin'; // Replace with desired role
  const username = 'admin'; // Replace with desired username
  const email = 'admin@gmail.com'; // Replace with desired email
 
    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      role,
      isApproved: true
    });

    await user.save();

    res.status(201).send({ user});

});


app.get('/admin/approved-users',
  authenticateUser,
  authorize(['admin']), // Ensure only admin can access
  async (req, res) => {
    try {
      // Fetch all users where isApproved is true
      const unapprovedUsers = await User.find({ isApproved: true }).select(
        'username email role'
      );

      if (unapprovedUsers.length === 0) {
        return res.status(200).json({ message: 'No unapproved users found.' });
      }

      res.status(200).json({
        message: 'Unapproved users retrieved successfully.',
        users: unapprovedUsers
      });
    } catch (error) {
      console.error('Error fetching unapproved users:', error);
      res.status(500).json({ message: 'An error occurred while fetching unapproved users.' });
    }
  }
);


async function deleteAllDocuments() {
  try {
    // await User.deleteMany({});
    // await Course.deleteMany({});
    // await Enrollment.deleteMany({});
    await AssignmentSubmission.deleteMany({});
    console.log('All documents in User, Course, and Enrollment collections have been deleted.');
  } catch (error) {
    console.error('Error deleting documents:', error);
  }
}
app.delete('/delete-documents', async (req, res) => {
  await deleteAllDocuments();
  res.send('All documents have been deleted from User, Course, and Enrollment collections.');
});


app.delete('/admin/users/:userId',
  authenticateUser,
  authorize(['admin']), // Only admins can delete users
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Fetch the user
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found.' });
      }

      if (user.role === 'student') {
        // For students, delete enrollments and submissions
        await Enrollment.deleteMany({ student: userId });
        await AssignmentSubmission.deleteMany({ student: userId });
      } else if (user.role === 'instructor') {
        // For instructors, delete their courses and related data
        const instructorCourses = await Course.find({ instructor: userId });

        for (const course of instructorCourses) {
          const courseId = course._id;

          // Delete enrollments for this course
          await Enrollment.deleteMany({ course: courseId });

          // Delete assignment submissions for this course's assignments
          const courseAssignments = course.assignments.map((assignment) => assignment._id);
          await AssignmentSubmission.deleteMany({ assignment: { $in: courseAssignments } });

          // Delete the course itself
          await Course.findByIdAndDelete(courseId);
        }
      }

      // Finally, delete the user
      await User.findByIdAndDelete(userId);

      res.status(200).json({ message: 'User and all related data have been deleted successfully.' });
    } catch (error) {
      console.error('Error deleting user:', error);
      res.status(500).json({ message: 'An error occurred while deleting the user.' });
    }
  }
);



app.put('/admin/courses/:courseId',
  authenticateUser,
  authorize(['admin']), // Only admins can edit courses
  async (req, res) => {
    try {
      const { courseId } = req.params;
      const { title, description } = req.body;

      // Validate input
      if (!title && !description) {
        return res
          .status(400)
          .json({ message: 'Please provide details to update the course.' });
      }

      // Find the course
      const course = await Course.findById(courseId);
      if (!course) {
        return res.status(404).json({ message: 'Course not found.' });
      }

      // Update the course fields if provided
      if (title) course.title = title;
      if (description) course.description = description;

      // Save the updated course
      await course.save();

      res.status(200).json({
        message: 'Course updated successfully.',
        course,
      });
    } catch (error) {
      console.error('Error updating course:', error);
      res.status(500).json({ message: 'An error occurred while updating the course.' });
    }
  }
);



app.get('/courses', authenticateUser, async (req, res) => {
  try {
    let courses;

    if (req.user.role === 'student') {
      // For students, fetch all courses they are enrolled in
      const enrollments = await Enrollment.find({ student: req.user._id })
        .populate({
          path: 'course',
          populate: { path: 'instructor', select: 'username _id' } // Populate instructor's name and ID
        });

      courses = enrollments.map(enrollment => {
        const course = enrollment.course.toObject();
        return {
          ...course,
          instructor: course.instructor // Ensure instructor info is included
        };
      });
    } else if (req.user.role === 'instructor') {
      // For instructors, fetch their own courses
      courses = await Course.find({ instructor: req.user._id }).populate(
        'instructor',
        'username _id' // Populate instructor's name and ID
      );
    } else {
      // For admins, fetch all courses
      courses = await Course.find().populate(
        'instructor',
        'username _id' // Populate instructor's name and ID
      );
    }

    res.status(200).json(courses);
  } catch (error) {
    console.error('Error fetching courses:', error);
    res.status(500).json({ message: 'An error occurred while fetching courses.' });
  }
});


app.delete('/admin/courses/:courseId',
  authenticateUser,
  authorize(['admin']), // Only admins or instructors can delete courses
  async (req, res) => {
    try {
      const { courseId } = req.params;

      // Fetch the course
      const course = await Course.findById(courseId);
      if (!course) {
        return res.status(404).json({ message: 'Course not found.' });
      }


      // Delete all enrollments related to the course
      await Enrollment.deleteMany({ course: courseId });

      // Delete all assignment submissions related to the course's assignments
      const courseAssignments = course.assignments.map(assignment => assignment._id);
      await AssignmentSubmission.deleteMany({ assignment: { $in: courseAssignments } });

      // Finally, delete the course
      await Course.findByIdAndDelete(courseId);

      res.status(200).json({ message: 'Course and all related data have been deleted successfully.' });
    } catch (error) {
      console.error('Error deleting course:', error);
      res.status(500).json({ message: 'An error occurred while deleting the course.' });
    }
  }
);


// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;