<?php

namespace App\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Transaction extends Model
{
    use HasFactory, SoftDeletes;

    protected $fillable = [
        'food_id', 'user_id', 'quantity', 'total', 'status', 'payment_url'
    ];

    //foreign key with food table
    public function food()
    {
        return $this->hasOne(Food::class, 'id', 'food_id');
    }

    //foreign key with user table
    public function user()
    {
        return $this->hasOne(User::class, 'id', 'user_id');
    }

    //epoch time
    public function getCreatedAtAttribute($value)
    {
        return Carbon::parse($value)->timestamp;
    }

    public function getUpdatedAtAttribute($value)
    {
        return Carbon::parse($value)->timestamp;
    }
}
