import { Test, TestingModule } from '@nestjs/testing';
import { RecommadationService } from './recommadation.service';

describe('RecommadationService', () => {
  let service: RecommadationService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RecommadationService],
    }).compile();

    service = module.get<RecommadationService>(RecommadationService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
