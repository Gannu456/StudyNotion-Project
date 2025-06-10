import axios from "axios";

export const axiosInstance = axios.create({});

export const apiConnector = (method, url, bodyData, headers, params) => {
  // Get the token from localStorage
  const token = localStorage.getItem("token");

  // Remove extra quotes if present
  const cleanedToken = token ? token.replace(/^"(.*)"$/, '$1') : null;

  // Add the token to the headers
  const authHeaders = cleanedToken ? { Authorization: `Bearer ${cleanedToken}` } : {};
  return axiosInstance({
    method: `${method}`,
    url: `${url}`,
    data: bodyData ? bodyData : null,
    headers: headers ? { ...headers, ...authHeaders } : authHeaders,
    params: params ? params : null,
  });
};

