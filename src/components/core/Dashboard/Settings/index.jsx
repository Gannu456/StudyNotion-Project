import React, { useState, useEffect } from "react";
import ChangeProfilePicture from "./ChangeProfilePicture";
import DeleteAccount from "./DeleteAccount";
import EditProfile from "./EditProfile";
import UpdatePassword from "./UpdatePassword";
import RegisterPasskey from "./RegisterPasskey";
import { useSelector, useDispatch } from "react-redux";
import { toast } from "react-hot-toast";
import { apiConnector } from "../../../../services/apiConnector";
import { settingsEndpoints } from "../../../../services/apis";
import { setUser } from "../../../../slices/profileSlice";

export default function Settings() {
  const { user } = useSelector((state) => state.profile);
  const dispatch = useDispatch();
  const [passkeys, setPasskeys] = useState([]);
  const [editingPasskey, setEditingPasskey] = useState(null);
  const [editedName, setEditedName] = useState("");

  useEffect(() => {
    if (user && user.passkeys) {
      setPasskeys(user.passkeys.map(passkey => ({ 
        ...passkey, 
        name: passkey.name || `Passkey ${passkey.credentialID.substring(0, 5)}` 
      })));
    }
  }, [user]);

  const handleRemovePasskey = async (credentialID) => {
    try {
      const { REMOVE_PASSKEY_API } = settingsEndpoints;
      const response = await apiConnector("POST", REMOVE_PASSKEY_API, {
        credentialID,
      });
  
      if (!response.data.success) {
        throw new Error(response.data.message);
      }
  
      toast.success("Passkey removed successfully");
  
      const updatedUser = {
        ...user,
        passkeys: user.passkeys.filter((passkey) => passkey.credentialID !== credentialID),
      };
      dispatch(setUser(updatedUser));
      setPasskeys(updatedUser.passkeys.map(passkey => ({ ...passkey, name: passkey.name || `Passkey ${passkey.credentialID.substring(0, 5)}` })));
  
    } catch (error) {
      console.error("Remove passkey error:", error);
      toast.error(error.message || "Failed to remove passkey");
    }
  };
  

  const handleEditName = (passkey) => {
    setEditingPasskey(passkey.credentialID);
    setEditedName(passkey.name);
  };

  const handleSaveName = async (credentialID) => {
    try {
      const { UPDATE_PASSKEY_NAME_API } = settingsEndpoints;
      const response = await apiConnector("POST", UPDATE_PASSKEY_NAME_API, {
        credentialID,
        name: editedName,
      });
  
      if (!response.data.success) {
        throw new Error(response.data.message);
      }
  
      toast.success("Passkey name updated successfully");
  
      const updatedPasskeys = passkeys.map((passkey) =>
        passkey.credentialID === credentialID ? { ...passkey, name: editedName } : passkey
      );
      setPasskeys(updatedPasskeys);
      setEditingPasskey(null);
  
      // Update user in redux
      const updatedUser = {
        ...user,
        passkeys: user.passkeys.map(p => p.credentialID === credentialID ? {...p, name:editedName} : p)
      }
      dispatch(setUser(updatedUser));
  
    } catch (error) {
      console.error("Update passkey name error:", error);
      toast.error(error.message || "Failed to update passkey name");
    }
  };

  return (
    <>
      <h1 className="mb-14 text-3xl font-medium text-richblack-5">
        Edit Profile
      </h1>
      <ChangeProfilePicture />
      <EditProfile />
      <UpdatePassword />
      <RegisterPasskey />
      {passkeys && passkeys.length > 0 && (
        <div className="mt-8">
          <h2 className="text-xl font-semibold mb-4 text-richblack-5">
            Registered Passkeys
          </h2>
          <table className="w-full text-left table-auto text-richblack-5">
            <thead>
              <tr>
                <th className="p-2 border-b text-richblack-5">Name</th>
                <th className="p-2 border-b text-richblack-5">Credential ID</th>
                <th className="p-2 border-b text-richblack-5">Actions</th>
              </tr>
            </thead>
            <tbody>
              {passkeys.map((passkey) => (
                <tr key={passkey.credentialID}>
                  <td className="p-2 border-b text-richblack-5">
                    {editingPasskey === passkey.credentialID ? (
                      <input
                        type="text"
                        value={editedName}
                        onChange={(e) => setEditedName(e.target.value)}
                        className="bg-richblack-800 text-richblack-5 p-1 rounded"
                      />
                    ) : (
                      passkey.name
                    )}
                  </td>
                  <td className="p-2 border-b text-richblack-5">
                    {passkey.credentialID.substring(0, 20)}...
                  </td>
                  <td className="p-2 border-b text-richblack-5">
                    {editingPasskey === passkey.credentialID ? (
                      <button
                        onClick={() => handleSaveName(passkey.credentialID)}
                        className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded mr-2"
                      >
                        Save
                      </button>
                    ) : (
                      <button
                        onClick={() => handleEditName(passkey)}
                        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded mr-2"
                      >
                        Edit
                      </button>
                    )}
                    <button
                      onClick={() => handleRemovePasskey(passkey.credentialID)}
                      className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded"
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <DeleteAccount />
    </>
  );
}