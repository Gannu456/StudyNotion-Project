import { useState } from "react";
import { AiOutlineEye, AiOutlineEyeInvisible } from "react-icons/ai";
import { useDispatch } from "react-redux";
import { Link, useNavigate } from "react-router-dom";
import { login, loginWithPasskey } from "../../../services/operations/authAPI";
import { toast } from "react-hot-toast";
import { startAuthentication } from "@simplewebauthn/browser";
import { setToken } from "../../../slices/authSlice";

function LoginForm() {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });

  const [showPassword, setShowPassword] = useState(false);

  const { email, password } = formData;

  const handleOnChange = (e) => {
    setFormData((prevData) => ({
      ...prevData,
      [e.target.name]: e.target.value,
    }));
  };

  const handleOnSubmit = (e) => {
    e.preventDefault();
    dispatch(login(email, password, navigate));
  };

  const handlePasskeyLogin = async () => {
    try {
      console.log("Fetching authentication options...");
  
      // Step 1: Fetch authentication options
      const response = await dispatch(loginWithPasskey(email));
  
      console.log("Authentication Options Response:", response);
  
      if (!response || !response.success) {
        throw new Error(response?.message || "Failed to fetch passkey options.");
      }
  
      console.log("Starting authentication...");
  
      // Step 2: Start authentication with the options
      const credential = await startAuthentication({
        optionsJSON: response.options,
      });
  
      console.log("Authentication Credential:", credential);
  
      console.log("Verifying authentication response...");
  
      // Step 3: Verify the authentication response
      const verificationResponse = await dispatch(loginWithPasskey(email, credential));
  
      console.log("Verification Response:", verificationResponse);
  
      if (!verificationResponse || !verificationResponse.success) {
        throw new Error(verificationResponse?.message || "Passkey verification failed.");
      }
  
      console.log("Saving token and navigating to dashboard...");
  
      // Step 4: Save the token and navigate to the dashboard
      dispatch(setToken(verificationResponse.token));
      navigate("/dashboard/my-profile");
    } catch (error) {
      console.error("Error during passkey login:", error);
      toast.error(error.message || "Failed to login with passkey.");
    }
  };

  return (
    <form onSubmit={handleOnSubmit} className="mt-6 flex w-full flex-col gap-y-4">
      <label className="w-full">
        <p className="mb-1 text-[0.875rem] leading-[1.375rem] text-richblack-5">
          Email Address <sup className="text-pink-200">*</sup>
        </p>
        <input
          required
          type="text"
          name="email"
          value={email}
          onChange={handleOnChange}
          placeholder="Enter email address"
          className="form-style w-full"
        />
      </label>
      <label className="relative">
        <p className="mb-1 text-[0.875rem] leading-[1.375rem] text-richblack-5">
          Password <sup className="text-pink-200">*</sup>
        </p>
        <input
          required
          type={showPassword ? "text" : "password"}
          name="password"
          value={password}
          onChange={handleOnChange}
          placeholder="Enter Password"
          className="form-style w-full !pr-10"
        />
        <span
          onClick={() => setShowPassword((prev) => !prev)}
          className="absolute right-3 top-[38px] z-[10] cursor-pointer"
        >
          {showPassword ? (
            <AiOutlineEyeInvisible fontSize={24} fill="#AFB2BF" />
          ) : (
            <AiOutlineEye fontSize={24} fill="#AFB2BF" />
          )}
        </span>
        <Link to="/forgot-password">
          <p className="mt-1 ml-auto max-w-max text-xs text-blue-100">
            Forgot Password
          </p>
        </Link>
      </label>
      <button
        type="submit"
        className="mt-6 rounded-[8px] bg-yellow-50 py-[8px] px-[12px] font-medium text-richblack-900"
      >
        Sign In
      </button>
      <button
        type="button"
        onClick={handlePasskeyLogin}
        className="mt-4 rounded-[8px] bg-blue-50 py-[8px] px-[12px] font-medium text-richblack-900"
      >
        Login with Passkey
      </button>
    </form>
  );
}

export default LoginForm;