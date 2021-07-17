<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;

class AuthController extends Controller
{
    public function register(RegisterRequest $request) {
        $user = User::Create(['password' => bcrypt($request->password)] + $request->validated());
        $token = $user->createToken('auth_token')->plainTextToken;
        return [
            'access_token' => $token,
            'token_type' => 'Bearer'
        ];
    }

    public function login(LoginRequest $request) {
        if(!Auth::attempt($request->only('email', 'password'))) {
            return response()->json(['error' => 'Invalid email or password'], 401);
        }

        /* Valid user */
        $user =  $request->user();
        $token = $user->createToken('auth_token')->plainTextToken;
        return [
            'access_token' => $token,
            'token_type' => 'Bearer'
        ];
    }

    public function userInfo(Request $user) {
        return $user->user();
    }
}