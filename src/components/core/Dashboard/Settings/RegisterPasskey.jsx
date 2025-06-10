import { useState } from "react";
import { toast } from "react-hot-toast";
import { apiConnector } from "../../../../services/apiConnector";
import { settingsEndpoints } from "../../../../services/apis";
import { useSelector } from "react-redux";
import { startRegistration } from "@simplewebauthn/browser";

const { REGISTER_PASSKEY_API } = settingsEndpoints;

export default function RegisterPasskey() {
  const [loading, setLoading] = useState(false);
  const { token } = useSelector((state) => state.auth);

  const handleRegisterPasskey = async () => {
    setLoading(true);
    try {
      // Fetch registration options from the server
      const response = await apiConnector(
        "POST",
        REGISTER_PASSKEY_API,
        {},
        { Authorization: `Bearer ${token}` }
      );
  
      console.log("REGISTER_PASSKEY_API API RESPONSE............", response);
  
      if (!response.data.success) {
        throw new Error(response.data.message);
      }
  
      const { options } = response.data;
  
      if (!options) {
        throw new Error("No credential options received from the server.");
      }
  
      console.log("Registration Options:", options); // Log the options
  
      // Ensure the options object contains a challenge
      if (!options.challenge) {
        throw new Error("Invalid options structure: missing challenge");
      }
  
      // Start the registration process
      const credential = await startRegistration({
        optionsJSON: options, // Wrap options in an object with optionsJSON
      });
  
      console.log("Credential from browser:", credential); // Log the credential
  
      // Ensure the credential object is structured correctly
      const verificationPayload = {
        id: credential.id,
        rawId: credential.rawId,
        response: {
          attestationObject: credential.response.attestationObject,
          clientDataJSON: credential.response.clientDataJSON,
        },
        type: credential.type,
      };
  
      console.log("Verification payload:", verificationPayload); // Log the payload
  
      // Send the attestation response to the server for verification
      const verificationResponse = await apiConnector(
        "POST",
        REGISTER_PASSKEY_API + "/verify",
        { credential: verificationPayload },
        { Authorization: `Bearer ${token}` }
      );
  
      console.log("Verification response:", verificationResponse); // Log the verification response
  
      if (!verificationResponse.data.success) {
        throw new Error(verificationResponse.data.message);
      }
  
      toast.success("Passkey registered successfully.");
    } catch (error) {
      console.error("Error registering passkey:", error);
      toast.error(error.message || "Failed to register passkey.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="my-10 flex flex-col gap-y-6 rounded-md border-[1px] border-richblack-800 bg-richblack-800 p-8">
      <h2 className="text-lg font-semibold text-richblack-5">Register Passkey</h2>
      <div className="flex items-center justify-between">
        <p className="text-sm text-richblack-400">
          Register a passkey for passwordless login.
        </p>
        <button
          onClick={handleRegisterPasskey}
          className="rounded-md bg-yellow-50 px-5 py-2 font-semibold text-richblack-900"
          disabled={loading}
        >
          {loading ? "Registering..." : "Register Passkey"}
        </button>
      </div>
    </div>
  );
}