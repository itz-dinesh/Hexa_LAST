// Profile.jsx
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const Profile = () => {
  const [profileData, setProfileData] = useState(null);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('token');

    if (!token) {
      navigate('/login'); // Redirect to login if no token is found
      return;
    }

    const fetchProfile = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/profile', {
          headers: {
            Authorization: token, // Attach the token to the request
          },
        });
        setProfileData(response.data);
      } catch (err) {
        setError('Failed to fetch profile');
      }
    };

    fetchProfile();
  }, [navigate]);

  if (error) {
    return <p>{error}</p>;
  }

  return (
    <div>
      <h2>Profile</h2>
      {profileData ? (
        <div>
          <p>Name: {profileData.firstName} {profileData.lastName}</p>
          <p>Email: {profileData.email}</p>
          {/* Add other profile information */}
        </div>
      ) : (
        <p>Loading...</p>
      )}
    </div>
  );
};

export default Profile;
