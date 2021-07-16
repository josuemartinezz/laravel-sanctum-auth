<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Requests\Auth\StoreRequest;

class AuthController extends Controller
{
    public function register(StoreRequest $request) {
        $user = User::Create(['password' => bcrypt($request->password)] + $request->validated());
        $token = $user->createToken('auth_token')->plainTextToken;
        return [
            'user' => $user,
            'token' => [
                'personal_token' => $token,
                'type' => 'Bearer'
            ]
        ];
    }

    public function login(Request $request) {
        if(!Auth::attempt($request->only('email', 'password'))) {
            return [
                'error' => 'Invalid email or password'
            ];
        }

        $user = User::where('email', $request->email)->first();
        $token = $user->createToken('auth_token')->plainTextToken;
        return [
            'user' => $user,
            'token' => [
                'personal_token' => $token,
                'type' => 'Bearer'
            ]
        ];
    }

    public function userInfo(Request $user) {
        return $user->user();
    }
}
