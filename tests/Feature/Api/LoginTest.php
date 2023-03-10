<?php

namespace Tests\Feature\Api;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Laravel\Passport\Passport;
use Mockery\Generator\StringManipulation\Pass\Pass;
use Tests\TestCase;

class LoginTest extends TestCase
{
    /**
     * A basic feature test example.
     *
     * @return void
     */
    use RefreshDatabase;
    protected function setUp(): void
    {
        parent::setUp(); // TODO: Change the autogenerated stub
        \Artisan::call('passport:install',['-vvv' => true]);
    }
    public function test_a_user_can_login_with_email_and_password()
    {
        $this->withoutExceptionHandling();

        $user = \App\Models\User::factory()->create([
            'password' => 'secret',
        ]);
        Passport::actingAs($user);
        $response = $this->post(route('api.login'),[
            'email' =>$user->email,
            'password' => 'secret'
        ])
            ->assertOk();
        $this->assertArrayHasKey('token',$response->json());
    }

}
