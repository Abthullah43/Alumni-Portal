from flask import Flask, request, render_template, redirect, url_for, session,jsonify
import sqlite3 # Replaces pandas and openpyxl for direct DB operations
import pandas as pd # Keep pandas for data manipulation if still needed elsewhere, review later
import os
import json
# import openpyxl # No longer needed for core data operations
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from flask import flash
import random
from flask import jsonify

app = Flask(__name__, static_folder="static")
app.secret_key = 'your_secret_key'

# Get the directory where the app.py file is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_NAME = "alumni_data.db" # Centralized database name

# Temporary storage for filtered results - this might also be moved to DB or session
RESULTS_FILE = "filtered_results.json" 

def get_db_connection():
    """Creates a connection to the SQLite database."""
    conn = sqlite3.connect(os.path.join(BASE_DIR, DATABASE_NAME))
    conn.row_factory = sqlite3.Row # Makes rows accessible by column name
    return conn

def sanitize_col_name(name):
    """Sanitize column name to match an SQL-friendly name."""
    return "".join(c if c.isalnum() else "_" for c in str(name))

# No more global loading of Excel files; data will be fetched on demand.

# Route for login
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            username = request.form.get("username", "").strip()
            password_form = request.form.get("password", "").strip() # Renamed to avoid conflict
            
            print(f"Login attempt for username: {username}")
            
            if not username or not password_form:
                error = "Username and password are required."
                return render_template("index.html", error=error)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Column names in DB are sanitized: 'Full Name' -> 'Full_Name', 'Password' -> 'Password'
            # Assuming 'Full_Name' and 'Password' are the sanitized column names in the 'students' table.
            # Case-insensitive username comparison using LOWER() SQL function
            cursor.execute("SELECT * FROM students WHERE LOWER(Full_Name) = LOWER(?)", (username,))
            user_record = cursor.fetchone()
            conn.close()
            
            print(f"Found user_record: {user_record}") # Debug log
            
            if user_record and user_record["Password"] == password_form: # Direct comparison
                session['logged_in'] = True
                session['username'] = user_record["Full_Name"] # Store actual name from DB
                print(f"Successful login for user: {user_record['Full_Name']}")
                return redirect(url_for("homepage"))
            else:
                error = "Invalid Username or Password. Please try again."
                print(f"Failed login attempt for user: {username}")
                return render_template("index.html", error=error)
                
        except sqlite3.Error as e:
            print(f"Database error during login: {e}")
            error = "System error. Please try again later."
            return render_template("index.html", error=error)
        except Exception as e:
            print(f"Unexpected error during login: {e}")
            error = "An unexpected error occurred. Please try again."
            return render_template("index.html", error=error)
    
    return render_template("index.html")

# Route for homepage
@app.route("/Homepage.html")
@app.route("/homepage")
def homepage():
    if not session.get('logged_in'):
        return redirect(url_for("login"))
    return render_template("Homepage.html")

#Route for index
@app.route("/index.html")
def BacktoLogin():
    return render_template("index.html")

# Route for registration form
@app.route("/Registration.html")
def registration():
    return render_template("Registration.html")

# Route for registration form processing
otp_storage = {}

@app.route("/send_otp", methods=["POST"])
def send_otp():
    email = request.form.get("email", "").strip()
    if not email:
        return jsonify({"error": "Email is required"}), 400

    otp = str(random.randint(100000, 999999))
    otp_storage[email] = otp

    try:
        msg = MIMEText(f"Your OTP for Alumni Registration is: {otp}")
        msg["Subject"] = "Alumni Registration OTP"
        msg["From"] = "alumniconnect.uit@gmail.com"
        msg["To"] = email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login("alumniconnect.uit@gmail.com", "gxdn wwrm kjpz wlqy")
            smtp.sendmail("alumniconnect.uit@gmail.com", email, msg.as_string())

        return jsonify({"success": "OTP sent successfully."})
    except Exception as e:
        print(f"Email send error: {e}")
        return jsonify({"error": "Failed to send OTP"}), 500

@app.route("/register_with_otp", methods=["POST"])
def register_with_otp():
    name = request.form.get("name").strip()
    roll = request.form.get("roll_number").strip()
    email = request.form.get("email").strip()
    phone = request.form.get("phone").strip()
    pwd = request.form.get("password")
    cpwd = request.form.get("confirm_password")
    otp = request.form.get("otp")

    if pwd != cpwd:
        return render_template("Registration.html", error="Passwords do not match.")

    if otp_storage.get(email) != otp:
        return render_template("Registration.html", error="Invalid OTP.")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM students WHERE LOWER(Email) = LOWER(?)", (email,))
    if cursor.fetchone():
        conn.close()
        return render_template("Registration.html", error="Email already registered.")

    cursor.execute("INSERT INTO students (Full_Name, Roll_Number, Email, Phone_No_, Password) VALUES (?, ?, ?, ?, ?)",
                   (name, roll, email, phone, pwd))
    conn.commit()
    conn.close()

    return redirect(url_for("login"))


otp_forgot_password_storage = {}

@app.route("/send_otp_forgot_password", methods=["POST"])
def send_otp_forgot_password():
    email = request.form.get("email", "").strip()
    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM students WHERE LOWER(Email) = LOWER(?)", (email.lower(),))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Email not registered"}), 400

    otp = str(random.randint(100000, 999999))
    otp_forgot_password_storage[email] = otp

    try:
        msg = MIMEText(f"Your OTP to reset password is: {otp}")
        msg["Subject"] = "Password Reset OTP"
        msg["From"] = "alumniconnect.uit@gmail.com"
        msg["To"] = email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login("alumniconnect.uit@gmail.com", "gxdn wwrm kjpz wlqy")
            smtp.sendmail("alumniconnect.uit@gmail.com", email, msg.as_string())

        return jsonify({"success": "OTP sent successfully."})
    except Exception as e:
        print(f"Email send error (forgot password): {e}")
        return jsonify({"error": "Failed to send OTP"}), 500

@app.route("/verify_otp_forgot_password", methods=["POST"])
def verify_otp_forgot_password():
    email = request.form.get("email", "").strip()
    otp = request.form.get("otp", "").strip()
    new_password = request.form.get("new_password", "")

    if not email or not otp or not new_password:
        return jsonify({"error": "All fields are required"}), 400

    stored_otp = otp_forgot_password_storage.get(email)
    if not stored_otp or stored_otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE students SET Password = ? WHERE LOWER(Email) = LOWER(?)", (new_password, email.lower()))
        conn.commit()
        conn.close()

        otp_forgot_password_storage.pop(email, None)  # OTP use ho gaya, hatao

        return jsonify({"success": "Password updated successfully"})
    except Exception as e:
        print(f"Error updating password: {e}")
        return jsonify({"error": "Failed to update password"}), 500

# Route for profile page
@app.route("/profile")
def profile():
    if not session.get('logged_in'):
        return redirect(url_for("login"))
    return render_template("Profile.html")

# Route for updating profile
@app.route("/update_profile", methods=["POST"])
def update_profile():
    if not session.get('logged_in'):
        return redirect(url_for("login"))
    
    try:
        # Get form data
        full_name = request.form.get("fullName", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        roll_number = request.form.get("rollNumber", "").strip()
        current_password = request.form.get("currentPassword", "").strip()
        new_password = request.form.get("newPassword", "").strip()
        
        # Get current user from session
        current_username = session.get('username')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify current password
        cursor.execute("SELECT * FROM students WHERE Full_Name = ?", (current_username,))
        user_record = cursor.fetchone()
        
        if not user_record or user_record["Password"] != current_password:
            conn.close()
            flash("Current password is incorrect!", "error")
            return redirect(url_for("profile"))
        
        # Check if email is being used by another user
        if email != user_record["Email"]:
            cursor.execute("SELECT * FROM students WHERE LOWER(Email) = LOWER(?) AND Full_Name != ?", 
                          (email, current_username))
            if cursor.fetchone():
                conn.close()
                flash("Email is already being used by another user!", "error")
                return redirect(url_for("profile"))
        
        # Update user information
        update_password = new_password if new_password else current_password
        
        cursor.execute("""
            UPDATE students 
            SET Full_Name = ?, Email = ?, Phone_No_ = ?, Roll_Number = ?, Password = ?
            WHERE Full_Name = ?
        """, (full_name, email, phone, roll_number, update_password, current_username))
        
        conn.commit()
        conn.close()
        
        # Update session with new username if changed
        session['username'] = full_name
        
        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))
        
    except sqlite3.Error as e:
        print(f"Database error in update_profile: {e}")
        flash("Error updating profile. Please try again.", "error")
        return redirect(url_for("profile"))
    except Exception as e:
        print(f"Error in update_profile: {e}")
        flash("An unexpected error occurred.", "error")
        return redirect(url_for("profile"))


# Route for about page
@app.route("/about")
def about():
    if not session.get('logged_in'):
        return redirect(url_for("login"))
    return render_template("about.html")

# Route for feedback page
@app.route('/feedback')
def feedback():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('feedback.html')

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if request.method == "POST":
        # Extract form data
        rating = request.form.get("rating")
        name = request.form.get("name")
        email = request.form.get("email")
        feedback_text = request.form.get("feedback") # Renamed

        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Column in DB is 'Message', not 'Feedback'
            cursor.execute("INSERT INTO feedback (Rating, Name, Email, Message) VALUES (?, ?, ?, ?)",
                           (rating, name, email, feedback_text))
            conn.commit()
            flash("Feedback submitted successfully!", "success")
            print(f"Feedback submitted by {name}")
        except sqlite3.Error as e:
            print(f"Database error submitting feedback: {e}")
            flash("Error submitting feedback. Please try again.", "error")
        finally:
            if conn:
                conn.close()
        
        return redirect(url_for('feedback'))

# Route for request form
@app.route("/request", methods=["GET", "POST"])
def request_form():
    if not session.get('logged_in'):
        return redirect(url_for("login"))

    if request.method == "POST":
        conn = None  # Initialize conn to None
        try:
            field = request.form.get("field", "").strip()
            location = request.form.get("location", "").strip()
            batch = request.form.get("batch", "").strip() # Ensure batch is treated as string for query
            company = request.form.get("company", "").strip()
            user_input = request.form.get("keyword", "").strip()

            conn = get_db_connection()
            
            # Sanitize table name for alumni data
            # The field from the form corresponds to the sheet name suffix
            # e.g., if field is "EL", table is "alumni_EL"
            alumni_table_name = f"alumni_{sanitize_col_name(field)}" # Use sanitize_col_name for consistency

            # Check if the alumni table exists
            cursor_check = conn.cursor()
            cursor_check.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (alumni_table_name,))
            table_exists = cursor_check.fetchone()

            if not table_exists:
                 # Try with "ALL" as a fallback if specific field table doesn't exist or if field is "ALL"
                alumni_table_name_all = "alumni_ALL"
                cursor_check.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (alumni_table_name_all,))
                if cursor_check.fetchone():
                    alumni_table_name = alumni_table_name_all
                    print(f"Field specific table for '{field}' not found, using '{alumni_table_name_all}'.")
                else: # If neither specific nor ALL table exists
                    print(f"No table found for field: {field} (tried {alumni_table_name}) or {alumni_table_name_all}")
                    return f"No data found for the selected field: {field}", 404


            # Base query
            query = f"SELECT * FROM {alumni_table_name} WHERE 1=1"
            params = []

            all_countries_selected = request.form.get("all_countries") == "on"
            if not all_countries_selected and location:
                # Assuming 'Location' is a sanitized column name
                query += " AND LOWER(Location) LIKE LOWER(?)"
                params.append(f"%{location}%")
            
            if batch and batch != "All": # Assuming 'Batch' is a sanitized column name
                query += " AND Batch = ?" # Batch should be an exact match
                params.append(batch)

            all_companies_selected = request.form.get("all_companies") == "on"
            if not all_companies_selected and company:
                # Assuming 'Experience' is a sanitized column name where company info might be
                query += " AND LOWER(Experience) LIKE LOWER(?)"
                params.append(f"%{company}%")

            # Fetch data into pandas DataFrame for keyword filtering and further processing
            # This part can be optimized to do more in SQL if performance becomes an issue
            df = pd.read_sql_query(query, conn, params=params)
            
            # Ensure column names are sanitized if we proceed with pandas from here
            # However, if read_sql_query gives us good names, this might not be needed
            # For safety, let's assume pandas might need sanitized names if we operate on df.columns directly
            df.columns = [sanitize_col_name(col) for col in df.columns]


            # Step 4: Get keywords from User_Input
            keywords = user_input
            keyword_list = [kw.strip().lower() for kw in keywords.split(",") if kw.strip()]
            print(f"Keyword list: {keyword_list}")

            # Step 5: Filter by Keywords using pandas
            if not df.empty and keyword_list:
                # Ensure these columns exist and are sanitized
                search_cols_sanitized = [sanitize_col_name(c) for c in ['Headline', 'About Us', 'Experience', 'Education']]
                # Filter out columns not present in the DataFrame to avoid KeyError
                actual_search_cols = [col for col in search_cols_sanitized if col in df.columns]

                if not actual_search_cols:
                    print("Warning: None of the specified keyword search columns found in the table.")
                    df['Match_Count'] = 0 # Avoid error if no columns to search
                else:
                    def keyword_match_count(row):
                        return sum(
                            any(kw in str(row[col]).lower() for kw in keyword_list)
                            for col in actual_search_cols if pd.notna(row[col]) # check for NaN
                        )
                    df['Match_Count'] = df.apply(keyword_match_count, axis=1)
                    df = df[df['Match_Count'] > 0]

            # Step 6: Sort by Match Count
            if not df.empty and 'Match_Count' in df.columns:
                df = df.sort_values(by="Match_Count", ascending=False)

            # Email extraction and store in session
            # Assuming 'Email_address' is the sanitized column name
            email_col_sanitized = sanitize_col_name('Email address')
            if email_col_sanitized in df.columns:
                session['filtered_alumni_emails'] = df[email_col_sanitized].tolist()
            else:
                session['filtered_alumni_emails'] = []
                print(f"Warning: Column '{email_col_sanitized}' (for emails) not found in results.")
            
            # Select specific columns for final output
            # These are the original names, ensure they are sanitized for selection from df
            display_cols_original = ["Name", "Discipline", "Batch", "Location", "Headline", "Linkedin"]
            display_cols_sanitized = [sanitize_col_name(c) for c in display_cols_original]
            
            # Filter to only include columns that actually exist in the DataFrame
            final_display_cols = [col for col in display_cols_sanitized if col in df.columns]
            
            if not final_display_cols:
                 print("Warning: None of the display columns found in the filtered data.")
                 # Fallback or error handling here
                 df_display = pd.DataFrame() # Empty DataFrame
            else:
                df_display = df[final_display_cols]
            
            # Apply hyperlink to Linkedin if the sanitized column exists
            linkedin_col_sanitized = sanitize_col_name('Linkedin')
            if linkedin_col_sanitized in df_display.columns:
                df_display.loc[:, linkedin_col_sanitized] = df_display[linkedin_col_sanitized].apply(
                    lambda url: f'<a href="{url}" target="_blank">{url}</a>' if pd.notna(url) and str(url).strip() != "" else ""
                )
            
            # Save filtered data to JSON file (still using this for results display)
            df_display.to_json(RESULTS_FILE, orient='records', default_handler=str) # Added default_handler for non-serializable data

            session['total_pages'] = -(-len(df_display) // 10)  # Ceiling division

            return redirect(url_for('display_results'))

        except sqlite3.Error as e:
            print(f"Database error in request_form: {e}")
            return f"A database error occurred: {e}", 500
        except pd.io.sql.DatabaseError as e: # Specific error for pandas SQL issues
            print(f"Pandas SQL error in request_form: {e}")
            # Check if it's a "no such table" error
            if "no such table" in str(e):
                 return f"No data found for the selected field: {field}. The table '{alumni_table_name}' may not exist.", 404
            return f"A data query error occurred: {e}", 500
        except Exception as e:
            print(f"An unexpected error occurred in request_form: {e}")
            import traceback
            traceback.print_exc() # Print detailed traceback for debugging
            return f"An error occurred: {e}", 500
        finally:
            if conn:
                conn.close()
                
    # For GET request, prepare list of available fields/sheets for the dropdown
    fields_available = []
    conn_get = None
    try:
        conn_get = get_db_connection()
        cursor_get = conn_get.cursor()
        cursor_get.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'alumni_%'")
        tables = cursor_get.fetchall()
        # Extract the part after 'alumni_' and replace '_' with space for display, if desired
        # Or keep it simple: extract the suffix after "alumni_"
        fields_available = [table['name'].replace('alumni_', '', 1) for table in tables if table['name'] != 'alumni_ALL']
        # Ensure 'ALL' is an option if alumni_ALL table exists
        cursor_get.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alumni_ALL'")
        if cursor_get.fetchone():
            if 'ALL' not in fields_available : # Ensure 'ALL' itself is available as an option if its table exists
                 fields_available.append('ALL') # Or handle 'ALL' specifically in template
        fields_available.sort()


    except sqlite3.Error as e:
        print(f"Database error fetching fields for request_form: {e}")
        # Handle error, maybe pass empty list or default fields
    finally:
        if conn_get:
            conn_get.close()
            
    return render_template("request_form.html", fields=fields_available if fields_available else ['CS', 'EL', 'CE', 'TE', 'ALL']) # Provide default if fetch fails


@app.route("/results")
def display_results():
    if not os.path.exists(RESULTS_FILE):
        return redirect(url_for("request_form"))

    try:
        with open(RESULTS_FILE, 'r') as f:
            filtered_data = pd.DataFrame(json.load(f))

        table_rows_html = filtered_data.to_html(
            classes="table table-bordered",
            index=False,
            escape=False,
            header=False
        )

        return render_template("results.html", results=table_rows_html)

    except Exception as e:
        return f"An error occurred while displaying results: {e}", 500

@app.route("/send-message-to-alumni", methods=['POST'])
def send_message_to_alumni():
    conn = None
    try:
        data = request.get_json()
        message = data.get('message')

        if not message:
            return jsonify({'error': 'Message is required'}), 400

        alumni_emails_session = session.get('filtered_alumni_emails', [])
        selected_indexes = data.get('selectedIndexes', []) # These are indices for alumni_emails_session
        
        target_alumni_emails = []
        if selected_indexes: # If specific alumni are selected from the displayed list
            target_alumni_emails = [alumni_emails_session[i] for i in selected_indexes if i < len(alumni_emails_session)]
        else: # If "Send to All Filtered" was clicked (or no selection implies all)
             # Consider if 'filtered_alumni_emails' should be used directly or if an explicit "send to all" is different.
             # For now, if no specific indexes, but there are filtered emails, send to all of them.
             # If selected_indexes is empty, the UI should clarify if it means "none" or "all filtered".
             # Current logic might send to no one if selected_indexes is empty.
             # Let's assume UI sends selectedIndexes, or a flag for "all filtered".
             # If selected_indexes is truly empty (e.g. no one checked), this is correct.
             pass # target_alumni_emails remains empty if selected_indexes is empty.

        if not target_alumni_emails: # Adjusted this condition
            return jsonify({'error': 'No alumni selected or no emails to send to.'}), 400


        # Get sender's (logged-in user's) details from 'students' table
        username = session.get('username')
        if not username:
            return jsonify({'error': 'User session expired or not found. Please log in again.'}), 401

        conn = get_db_connection()
        cursor = conn.cursor()
        # Assuming 'Full_Name' is the sanitized column in 'students'
        cursor.execute("SELECT Email, Full_Name FROM students WHERE Full_Name = ?", (username,))
        user_info_row = cursor.fetchone()
        
        if not user_info_row:
            return jsonify({'error': 'User information not found in database.'}), 500

        user_email = user_info_row["Email"]
        # Phone_No might be 'Phone_No' or 'Phone_No_' depending on sanitization logic for "Phone No."
        # Let's check common sanitization: "Phone No" -> "Phone_No"
        user_name = user_info_row["Full_Name"]
        
        conn.close() # Close DB connection once user info is fetched

        full_message = f"""Respected Alumni,

        I hope this message finds you well. I am a student from the UIT University and I am reaching out to seek your valuable guidance and mentorship.

        Please find my message below.

        {message}

        ---
        Sent by:
        Name: {user_name}
        Email: {user_email}
        """

        sender_email_account = "alumniconnect.uit@gmail.com" # Make sure this is a config/env var
        password_email_account = "gxdn wwrm kjpz wlqy" # IMPORTANT: Store securely, not in code!

        # Send email
        # ... (email sending logic remains the same)
        # This part is complex and has external dependencies (smtplib). Assuming it works.
        # For safety, wrap in try-except if not already robust.
        try:
            msg = MIMEText(full_message)
            msg['Subject'] = f'Message from UIT Student: {user_name}'
            msg['From'] = sender_email_account
            msg['To'] = ", ".join(target_alumni_emails) # Send to all selected alumni

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
                smtp_server.login(sender_email_account, password_email_account)
                smtp_server.sendmail(sender_email_account, target_alumni_emails, msg.as_string())
            
            print(f"Email sent successfully to: {', '.join(target_alumni_emails)}")
            return jsonify({'success': 'Message sent successfully!'})

        except smtplib.SMTPAuthenticationError:
            print("SMTP Authentication Error. Check email credentials.")
            return jsonify({'error': 'Failed to send email due to authentication error with the email server.'}), 500
        except smtplib.SMTPException as e:
            print(f"SMTP error occurred: {e}")
            return jsonify({'error': f'Failed to send email due to SMTP error: {e}'}), 500
        except Exception as e: # Catch any other errors during email sending
            print(f"An unexpected error occurred while sending email: {e}")
            return jsonify({'error': f'An unexpected error occurred while sending the email: {e}'}), 500
            
    except sqlite3.Error as e:
        print(f"Database error in send_message_to_alumni: {e}")
        return jsonify({'error': f'A database error occurred: {e}'}), 500
    except Exception as e:
        print(f"Error in send_message_to_alumni: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500
    finally:
        if conn and conn: # Check if conn was assigned and is not None
            conn.close()

# Route for logout
@app.route("/logout")
def logout():
    session.clear()
    if os.path.exists(RESULTS_FILE):
        os.remove(RESULTS_FILE)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
