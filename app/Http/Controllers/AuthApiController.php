<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthApiController extends BaseController
{



    public function register(RegisterRequest $request)
    {

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),

        ]);
        $success['token'] =  $user->createToken('MyApp')->accessToken;
        $success['name'] =  $user->name;
        return $this->sendResponse($success, 'User register successfully.');
    }

    public function login(Request $request)
    {
        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])){
            $user = Auth::user();
            $success['token'] =  $user->createToken('MyApp')-> accessToken;
            $success['name'] =  $user->name;

            return $this->sendResponse($success, 'User login successfully.');
        }
        else{
            return $this->sendError('Unauthorised.', ['error'=>'Unauthorised']);
        }
    }

//    public function login(Request $request)
//    {
//        dd($request);
//        if (auth()->attempt($request->all())) {
//            return response([
//                'user' => auth()->user(),
//                'access_token' => auth()->user()->createToken('authToken')->accessToken
//            ], Response::HTTP_OK);
//        }
//
//        return response([
//            'message' => 'This User does not exist'
//        ], Response::HTTP_UNAUTHORIZED);
//    }

//    public function login(Request $request)
//    {
//        $data = [
//            'email' => $request->email,
//            'password' => $request->password
//        ];
//
//        if (auth()->attempt($data)) {
//            $token = auth()->user()->createToken('LaravelAuthApp')->accessToken;
//            return response()->json(['token' => $token], 200);
//        } else {
//            return response()->json(['error' => 'Unauthorised'], 401);
//        }
//    }
}
