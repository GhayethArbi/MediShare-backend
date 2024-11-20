import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RecommadationService } from './recommadation.service';
import { GoogleAIController } from './recommadation.controller';
import { Recommadation, RecommadationSchema } from './entities/recommadation.entity';
import { User, UserSchema } from '../auth/schemas/user.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Recommadation.name, schema: RecommadationSchema },
      { name: User.name, schema: UserSchema },
    ]),
  ],
  controllers: [GoogleAIController],
  providers: [RecommadationService],
  exports: [RecommadationService], // Export the service if used in other modules
})
export class RecommadationModule {}
