import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { Recommadation } from './entities/recommadation.entity';
import { User } from '../auth/schemas/user.schema';

@Injectable()
export class RecommadationService {
  private genAI: any;

  constructor(
    @InjectModel(Recommadation.name) private readonly recommadationModel: Model<Recommadation>,
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {
    const apiKey = process.env.API_KEY;
    if (!apiKey) {
      throw new Error('API_KEY is missing. Please set it in your environment variables.');
    }
    this.genAI = new GoogleGenerativeAI(apiKey);
  }

  // Generate content using Google Generative AI
  async generateContent(prompt: string): Promise<string> {
    try {
      const model = this.genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
      const result = await model.generateContent(prompt);
      return await result.response.text();
    } catch (error) {
      console.error('Error generating content:', error);
      throw new Error('Failed to generate content.');
    }
  }

  // Create a recommendation for a specific user
  async createRecommadation(userId: string, title: string, content: string): Promise<Recommadation> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const recommendation = new this.recommadationModel({
      title,
      content,
      user: user._id,
    });

    return recommendation.save();
  }

  // Fetch all recommendations for a specific user
  async getRecommadationsByUser(userId: string): Promise<Recommadation[]> {
    const user = await this.userModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.recommadationModel.find({ user: user._id });
  }

  // Fetch a specific recommendation by ID
  async getRecommadationById(recommendationId: string): Promise<Recommadation> {
    const recommendation = await this.recommadationModel.findById(recommendationId);
    if (!recommendation) {
      throw new NotFoundException('Recommendation not found');
    }
    return recommendation;
  }

  // Update a recommendation by ID
  async updateRecommadation(recommendationId: string, updates: Partial<Recommadation>): Promise<Recommadation> {
    const recommendation = await this.recommadationModel.findByIdAndUpdate(recommendationId, updates, {
      new: true,
    });
    if (!recommendation) {
      throw new NotFoundException('Recommendation not found');
    }
    return recommendation;
  }

  // Delete a recommendation by ID
  async deleteRecommadation(recommendationId: string): Promise<{ message: string }> {
    const result = await this.recommadationModel.findByIdAndDelete(recommendationId);
    if (!result) {
      throw new NotFoundException('Recommendation not found');
    }
    return { message: 'Recommendation successfully deleted' };
  }
}
