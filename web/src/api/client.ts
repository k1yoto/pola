import axios, { AxiosError } from 'axios';
import type {
  SessionsResponse,
  PoliciesResponse,
  TEDResponse,
  ErrorResponse,
} from '../types/api';

// Use environment variable if set, otherwise use empty string for same-origin requests
const envApiUrl = import.meta.env.VITE_API_BASE_URL;
const API_BASE_URL = envApiUrl !== undefined ? envApiUrl : 'http://localhost:8080';

const apiClient = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// エラーハンドリングヘルパー
const handleError = (error: unknown): never => {
  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError<ErrorResponse>;
    if (axiosError.response?.data?.error) {
      throw new Error(axiosError.response.data.error);
    }
    if (axiosError.message) {
      throw new Error(axiosError.message);
    }
  }
  throw new Error('An unknown error occurred');
};

// API関数

export const getSessions = async (): Promise<SessionsResponse> => {
  try {
    const response = await apiClient.get<SessionsResponse>('/sessions');
    return response.data;
  } catch (error) {
    return handleError(error);
  }
};

export const getTED = async (): Promise<TEDResponse> => {
  try {
    const response = await apiClient.get<TEDResponse>('/ted');
    return response.data;
  } catch (error) {
    return handleError(error);
  }
};

export const getPolicies = async (): Promise<PoliciesResponse> => {
  try {
    const response = await apiClient.get<PoliciesResponse>('/policies');
    return response.data;
  } catch (error) {
    return handleError(error);
  }
};

export default apiClient;
